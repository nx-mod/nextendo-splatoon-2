// Command s2 runs the Splatoon 2 online servers (auth + secure) on the Nextendo NEX
// stack — a from-scratch NEX implementation with no third-party dependencies.
// It runs the auth and secure servers in one process.
//
// Two NEX servers run in one process:
//   - auth   (:443)   TicketGranting — LoginEx issues the Kerberos ticket. (S2 logs in
//     with LoginEx 0x2, unlike SSBU which uses ValidateAndRequestTicketWithParam 0x6.)
//   - secure (:60004) SecureConnection + matchmaking + NAT-traversal + ranking, plus the
//     S2-specific DataStore replay and Utility methods.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

const (
	// accessKey is Splatoon 2's NEX access key (MK8 uses 09c1c475, SSBU 9587602b).
	accessKey      = "4eb18d39"
	nexVersion     = 40000
	securePID      = 2
	sessionKeyLen  = 32
	// sniHost is an optional SNI hostname advertised to clients (set via NEXTENDO_HOST).
	sniHost = ""
	// s2AppID identifies Splatoon 2 to the account service's presence API.
	s2AppID = "0100f8f0000a2000"
)

var (
	nextendoHost = envOr("NEXTENDO_HOST", sniHost)
	authPort     = envOrInt("AUTH_PORT", 443)
	securePort   = envOrInt("SECURE_PORT", 60004)
	securePassword = envOr("NEXTENDO_SECURE_PASSWORD", "securepasswordplz1")
	certFile     = envOr("CERT_FILE", "cert.pem")
	keyFile      = envOr("KEY_FILE", "key.pem")

	// nextendoSecret signs "nx2." NEX login tokens issued by the account service. It MUST
	// be byte-identical to nextendo-account's secret or token validation fails.
	nextendoSecret = loadNextendoSecret()
	// requireAccount, when "1", rejects any login without a valid Nextendo token.
	requireAccount = os.Getenv("NEXTENDO_REQUIRE_ACCOUNT") == "1"
)

func main() {
	settings := nex.NewSwitchSettings(accessKey, nexVersion)

	// --- Auth server (:443) ---
	// "prudps" (PRUDP *Secure*), not "prudp": the scheme of this station URL is how the
	// client decides the target is a secure server and therefore hands over its Kerberos
	// ticket in CONNECT. With "prudp" the handshake completes but CONNECT carries an EMPTY
	// payload — no ticket, no session key — and the game dies once Pia needs the session
	// (DataStore reads still work, so menus look fine). The same applies to the SSBU server.
	secureURL := nex.NewStationURL("prudps")
	secureURL.Set("address", nextendoHost)
	secureURL.SetInt("port", securePort)
	secureURL.SetInt("CID", 1)
	secureURL.SetInt("PID", securePID)
	secureURL.SetInt("sid", 1)
	secureURL.SetInt("stream", 10)
	secureURL.SetInt("type", 2) // public

	authEndpoint := nex.NewEndpoint(settings)
	authCfg := &nex.AuthConfig{
		Settings:         settings,
		SecurePID:        securePID,
		SecurePassword:   securePassword,
		SecureStationURL: secureURL,
		ServerName:       "Nextendo",
		SessionKeyLength: sessionKeyLen,
		ResolveUser:      resolveUser,
	}
	authEndpoint.Register(nex.ProtocolTicketGranting, authCfg.Handler())
	authEndpoint.OnRMC = logRMC("Auth")
	authServer := nex.NewServer(authEndpoint)

	// --- Secure server (:60004) ---
	// The secure endpoint gets its OWN settings so it can negotiate PRUDP minor version 0
	// in its SYN-ACK (the supported-functions option encodes minorVersion|supportedFunc<<8),
	// which is what the retail secure server answered: option=0 where ours replied 5. Scoped
	// to the secure endpoint on purpose — the auth (:443) is a separate PRUDP server, and
	// SSBU's auth stopped receiving logins entirely when its minor version was forced to 0.
	secureSettings := nex.NewSwitchSettings(accessKey, nexVersion)
	secureSettings.PrudpMinorVersion = 0
	secureEndpoint := nex.NewEndpoint(secureSettings)
	secureEndpoint.SetSecureAccount(securePassword, securePID)

	mm := nex.NewMatchmaking()
	// Splatoon 2 predates Switch Pia 5.19: its proven server answers Register with a public
	// station of type=0x03 and NO Pa param, where SSBU answers type=0x0B + Pa. That one field
	// is the difference between the two titles; sending SSBU's shape here breaks S2.
	secureEndpoint.Register(nex.ProtocolSecureConnection, nex.SecureConnectionHandlerWithConfig(nex.LegacyPiaConfig()))
	secureEndpoint.Register(nex.ProtocolMatchmakeExtension, mm.ExtensionHandler())
	secureEndpoint.Register(nex.ProtocolMatchMaking, mm.MatchMakingHandler())
	secureEndpoint.Register(nex.ProtocolMatchMakingExt, mm.MatchMakingExtHandler())
	secureEndpoint.Register(nex.ProtocolNATTraversal, nex.NATTraversalHandler())
	// S2 extends Utility (0x6E) and needs DataStore (0x73) answered with Nintendo's real
	// bytes; Ranking (0x70) and MatchmakeExtension get S2's extra methods patched in.
	setupS2DatastoreReplay(secureEndpoint)
	setupS2Utility(secureEndpoint)
	setupS2Ranking(secureEndpoint)
	setupS2MatchmakeExtras(secureEndpoint, mm)

	logSecure := logRMC("Secure")
	secureEndpoint.OnRMC = func(c *nex.Connection, req *nex.RMCMessage) {
		logSecure(c, req)
		noteRMC(c, req)         // feed the monitoring dashboard
		notePresenceSeen(c.PID) // any packet from a PID = that account is playing S2 now
	}
	secureEndpoint.OnConnect = func(c *nex.Connection) {
		fmt.Printf("[S2 Secure] connected pid=%d id=%d addr=%s\n", c.PID, c.ID, c.RemoteAddr)
	}
	// Drop the player's lobbies when the connection dies. A gathering is otherwise only
	// removed when the client politely calls UnregisterGathering / EndParticipation, so a
	// client that crashes or errors out leaks its lobby forever: the monitoring fills with
	// phantom lobbies "searching" for a player who is long gone, and matchmaking can hand
	// those dead sessions to real players.
	secureEndpoint.OnDisconnect = func(c *nex.Connection) {
		mm.RemovePlayer(c.PID)
	}
	secureServer := nex.NewServer(secureEndpoint)

	// Monitoring: per-game /api/stats for the unified Nextendo dashboard.
	// Éviction automatique des connexions mortes. Sans elle, une session perdue (crash,
	// coupure, émulateur fermé) restait enregistrée indéfiniment : le joueur se voyait
	// refuser l'accès (« ce compte joue déjà ailleurs ») et les compteurs étaient faux.
	secureEndpoint.StartReaper()
	go startDashboard(secureEndpoint, mm)
	// Presence: report active PIDs to the account service so friends see "playing Splatoon 2".
	startPresenceReporter()

	// When the auth is fronted by a TLS-passthrough proxy (Traefik on the shared :443),
	// enable PROXY protocol so the auth sees the console's REAL IP.
	proxyProto := os.Getenv("NEXTENDO_PROXY_PROTOCOL") == "1"
	go func() {
		fmt.Printf("[S2 Auth] listening WSS :%d (proxyProto=%v, secure URL -> %s)\n", authPort, proxyProto, secureURL.String())
		var err error
		if proxyProto {
			err = authServer.ListenSecureProxy(authPort, certFile, keyFile)
		} else {
			err = authServer.ListenSecure(authPort, certFile, keyFile)
		}
		if err != nil {
			fmt.Printf("[S2 Auth] stopped: %v\n", err)
		}
	}()

	fmt.Printf("[S2 Secure] listening WSS :%d\n", securePort)
	if err := secureServer.ListenSecure(securePort, certFile, keyFile); err != nil {
		fmt.Printf("[S2 Secure] stopped: %v\n", err)
	}
}

// resolveUser maps a LoginEx username to an account. A valid "nx2." Nextendo token
// resolves to its persistent PID; anything else gets a stable anonymous PID derived from
// the username (so the same console keeps the same identity).
func resolveUser(username string, _ []byte) (uint64, []byte, bool) {
	// The source key encrypts the client ticket and is handed back as pSourceKey, so the
	// console decrypts it. It MUST be 32 bytes (the Switch kerberos key size).
	sk := sha256.Sum256([]byte("nextendo-src:" + username))
	sourceKey := sk[:]

	// 1. Signed nx2 token → the account's PERSISTENT PID (+ online gates).
	if pid, ok := nextendoPIDFromToken(username); ok {
		if allow, reason := nextendoOnlineCheck(pid, "ryujinx"); !allow {
			fmt.Printf("[Auth] pid=%d online REFUSÉ (%s)\n", pid, reason)
			return 0, nil, false
		}
		return pid, sourceKey, true
	}

	// 2. Numeric username. The emulator's "Connexion Nextendo" button sends the account's
	// OWN PID; a real CFW Switch sends its console baasUserID (a large NSA id) instead,
	// which we resolve to the account PID. Using the account PID verbatim keeps the NEX
	// identity = the account the game knows itself by (hashing it breaks Pia's
	// self-recognition → 2618-562 SessionKeepFailed).
	if n, err := strconv.ParseUint(username, 10, 64); err == nil && n >= 1800000000 {
		// FAILLE D AUTHENTIFICATION CONNUE. Ce chemin accepte un PID NU comme identite :
		// aucun jeton, aucune signature. Les PID etant sequentiels depuis 1800000001, il
		// suffit d envoyer le numero d un autre membre pour jouer sous son identite — et,
		// via la garde « un seul endroit », l empecher lui-meme de jouer.
		// On ne peut pas l interdire sechement : l emulateur distribue envoie precisement
		// ce PID nu. Le refus est donc derriere un interrupteur, a activer quand une build
		// envoyant le jeton nx2 signe sera deployee. En attendant on journalise chaque usage.
		if requireSignedToken() {
			fmt.Printf("[Auth] pid=%d REFUSE : identite par PID nu desactivee (jeton nx2 signe requis)\n", n)
			return 0, nil, false
		}
		fmt.Printf("[Auth] pid=%d identite par PID NU (non authentifiee — cf. NEXTENDO_REQUIRE_SIGNED_TOKEN)\n", n)
		pid, kind := n, "ryujinx"
		if n >= 1810000000 { // vraie Switch : NSA id -> PID de compte (online = comptes Nextendo UNIQUEMENT)
			kind = "switch"
			rp, st := resolveNSAtoPID(n)
			switch st {
			case nsaOK:
				pid = rp
				fmt.Printf("[Auth] NSA %d -> account pid=%d\n", n, pid)
			case nsaUnknown:
				fmt.Printf("[Auth] NSA %d REFUSÉ (aucun compte Nextendo)\n", n)
				return 0, nil, false
			case nsaUnreachable:
				fmt.Printf("[Auth] NSA %d REFUSÉ (serveur compte injoignable)\n", n)
				return 0, nil, false
			}
		}
		// GATES online : #6 e-mail vérifié + #5 un seul endroit + compte inconnu/désactivé.
		if allow, reason := nextendoOnlineCheck(pid, kind); !allow {
			fmt.Printf("[Auth] pid=%d online REFUSÉ (%s)\n", pid, reason)
			return 0, nil, false
		}
		return pid, sourceKey, true
	}

	// 3. Anonymous / no Nextendo identity. When requireAccount is on, online REQUIRES a
	// Nextendo account → reject (the game can't enter online mode).
	if requireAccount {
		fmt.Printf("[Auth] login anonyme REFUSÉ (compte Nextendo requis): %q\n", username)
		return 0, nil, false
	}
	return anonymousPID(username), sourceKey, true
}

// nextendoPIDFromToken validates a "nx2.<b64(pid.username.expiry)>.<b64(hmac)>" token
// signed by the account service (HMAC-SHA256, "nex:" prefix).
func nextendoPIDFromToken(s string) (uint64, bool) {
	if len(nextendoSecret) == 0 || !strings.HasPrefix(s, "nx2.") {
		return 0, false
	}
	parts := strings.Split(s[len("nx2."):], ".")
	if len(parts) != 2 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, nextendoSecret)
	mac.Write([]byte("nex:" + string(raw)))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return 0, false
	}
	f := strings.SplitN(string(raw), ".", 3) // pid.username.expiry
	if len(f) != 3 {
		return 0, false
	}
	pid, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0, false
	}
	if exp, err := strconv.ParseInt(f[2], 10, 64); err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	return pid, true
}

// loadNextendoSecret loads the shared NEX-token signing secret the SAME way
// nextendo-account does (its loadSecret): env NEXTENDO_SECRET as raw bytes if set,
// otherwise hex-decode the shared key file. The deployed account has no env → it
// hex-decodes the file, so we must too or the HMAC won't match.
func loadNextendoSecret() []byte {
	if v := os.Getenv("NEXTENDO_SECRET"); v != "" {
		return []byte(v)
	}
	path := envOr("NEXTENDO_SECRET_FILE", "nextendo_secret.key")
	if b, err := os.ReadFile(path); err == nil {
		if dec, derr := hex.DecodeString(strings.TrimSpace(string(b))); derr == nil && len(dec) >= 16 {
			return dec
		}
	}
	return nil
}

// anonymousPID derives a stable PID in the NEX user range from a username.
func anonymousPID(username string) uint64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(username))
	return 1800000000 + uint64(h.Sum32()%100000000)
}

func logRMC(tag string) func(*nex.Connection, *nex.RMCMessage) {
	return func(c *nex.Connection, req *nex.RMCMessage) {
		fmt.Printf("[S2 %s] pid=%d proto=%#x method=%d call=%d\n", tag, c.PID, req.Protocol, req.Method, req.CallID)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// requireSignedToken : quand true, seule une identite prouvee par un jeton nx2 SIGNE est
// acceptee au LoginEx ; un PID nu est refuse. Desactive par defaut car l emulateur
// actuellement distribue envoie encore le PID nu — a activer apres la prochaine release.
func requireSignedToken() bool {
	v := os.Getenv("NEXTENDO_REQUIRE_SIGNED_TOKEN")
	return v == "1" || v == "true"
}
