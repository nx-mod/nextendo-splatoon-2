package main

// Splatoon 2's extra Utility (0x6E) methods, plus the Ranking / MatchmakeExtension
// methods it calls that standard NEX doesn't define. Everything here answers a method
// that would otherwise return NotImplemented and stall the game.

import (
	"fmt"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

// Protocol ids S2 uses beyond the ones the core registers by name.
const (
	ProtocolDataStore uint16 = 0x73
	ProtocolUtility   uint16 = 0x6E
	ProtocolRanking   uint16 = 0x70
)

const (
	// Utility 0x6E.9 AcquireTagId(list<Uint64>) -> Uint64 pTagId. Post-login, in-session
	// sharing; never the login blocker.
	methodUtilityAcquireTagID uint32 = 9
	// Utility 0x6E.10 UpdateCurrentUser(UpdateCurrentUserParam) -> VOID. Its success GATES
	// S2's transition to network-ready: cAcquireNexUniqueID -> cUpdateCurrentUser ->
	// cNetworkReadySuccess. NotImplemented here made S2 fall to cNetworkReadyFailed and
	// disconnect (PlayReport lobby_error_event{error_from:3}).
	methodUtilityUpdateCurrentUser uint32 = 10

	// Ranking 0x70.18 GetFestivalResult (S2) / GetCompetitionInfo (MK8D) -> list.
	methodRankingGetFestivalResult uint32 = 18
	// Ranking 0x70.19 — another S2 fest list query, fired at the 8-player match START while a
	// splatfest is announced/active (seen LIVE: it was the last call before 2306-0103 once
	// 0x6d.8 ModifyCurrentGameAttribute was handled). Same family as 18/25, and — like them —
	// no real measured can exist (dead official servers, no live fest to proxy), so the
	// best-grounded answer is an empty list. NotImplemented here = Core::NotImplemented = 2306-0103.
	methodRankingGetFestivalRanking uint32 = 19
	// Ranking 0x70.25 GetEventMatchResult -> list. S2 calls it every ~6 min WHILE A
	// SPLATFEST IS ACTIVE; NotImplemented produced the 2306-0103 comm-error popup. No real
	// measured can ever exist (S2's official servers are dead, so a live splatfest could
	// never be proxy-measured), so an empty list is the best-grounded answer.
	methodRankingGetEventMatchResult uint32 = 25

	// MatchmakeExtension 0x6D.60 CustomGetSimplePlayingSession -> list<SimplePlayingSession>.
	// For a normal match (nobody in a tracked session yet) an empty list is valid and
	// unblocks the post-match sequence.
	methodMatchmakeExtGetSimplePlayingSession uint32 = 60
)

// setupS2Utility layers S2's extra Utility (0x6E) methods over the core ones.
//
// Layered, like Ranking and MatchmakeExtension below, rather than replacing: this handler
// used to answer only S2's own two methods and send everything else to NotImplemented,
// which silently hid the core's Utility from Splatoon 2 entirely — including
// AcquireNexUniqueIDWithPassword (0x6E.2), which a title only ever calls on a FRESH
// account. Those players got 2306-0103 while everyone else was fine.
func setupS2Utility(endpoint *nex.Endpoint) {
	base := nex.UtilityHandler()
	endpoint.Register(ProtocolUtility, func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		s := conn.Settings
		switch req.Method {
		case methodUtilityUpdateCurrentUser:
			// reference (proxy measured of a real Switch S2 online match,
			// a measurement -> resp_0x6e_m10.bin = 0 bytes):
			// Nintendo replies RMC SUCCESS with an EMPTY body. An earlier disassembly RCA
			// concluded this method returned a ~31-byte struct and had us send 64 zero
			// bytes; the measured overrode it. Do not "fix" this to a non-empty body on the
			// strength of a disasm again — measure it.
			fmt.Printf("[S2 Utility] UpdateCurrentUser pid=%d callID=%d reqLen=%d -> empty success\n",
				conn.PID, req.CallID, len(req.Body))
			return nex.NewRMCSuccess(s, ProtocolUtility, req.Method, req.CallID, nil)

		case methodUtilityAcquireTagID:
			// Return a benign non-zero tag id derived from the caller PID.
			tagID := conn.PID
			if tagID == 0 {
				tagID = 1
			}
			out := nex.NewStreamOut(s)
			out.U64(tagID)
			fmt.Printf("[S2 Utility] AcquireTagId -> pTagId=%d\n", tagID)
			return nex.NewRMCSuccess(s, ProtocolUtility, req.Method, req.CallID, out.Bytes())

		default:
			// Everything else is standard Utility — the core answers the settings queries
			// and hands out the NEX unique id. It still logs an UNHANDLED of its own for
			// anything neither of us knows, so a genuinely new method stays visible.
			return base(conn, req)
		}
	})
	fmt.Println("[S2 Utility] registered: UpdateCurrentUser(10), AcquireTagId(9) + core Utility")
}

// setupS2Ranking registers Ranking (0x70) with the two list-returning methods S2 calls.
func setupS2Ranking(endpoint *nex.Endpoint) {
	base := nex.RankingHandler()
	endpoint.Register(ProtocolRanking, func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		switch req.Method {
		case methodRankingGetFestivalResult, methodRankingGetFestivalRanking, methodRankingGetEventMatchResult:
			return emptyList(conn, ProtocolRanking, req, "Ranking")
		}
		return base(conn, req)
	})
	fmt.Println("[S2 Ranking] registered: GetFestivalResult(18), GetEventMatchResult(25)")
}

// setupS2MatchmakeExtras layers S2's extra MatchmakeExtension method over the core one.
func setupS2MatchmakeExtras(endpoint *nex.Endpoint, mm *nex.Matchmaking) {
	base := mm.ExtensionHandler()
	endpoint.Register(nex.ProtocolMatchmakeExtension, func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		if req.Method == methodMatchmakeExtGetSimplePlayingSession {
			return emptyList(conn, nex.ProtocolMatchmakeExtension, req, "MatchmakeExt")
		}
		return base(conn, req)
	})
	fmt.Println("[S2 MatchmakeExt] registered: CustomGetSimplePlayingSession(60)")
}

// emptyList answers with a NEX list of zero elements (u32 count = 0).
func emptyList(conn *nex.Connection, proto uint16, req *nex.RMCMessage, label string) *nex.RMCMessage {
	s := conn.Settings
	out := nex.NewStreamOut(s)
	out.U32(0)
	fmt.Printf("[S2 %s] method %d -> empty list\n", label, req.Method)
	return nex.NewRMCSuccess(s, proto, req.Method, req.CallID, out.Bytes())
}
