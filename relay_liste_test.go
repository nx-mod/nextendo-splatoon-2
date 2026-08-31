package main

import (
	"bufio"
	"os"
	"strings"
	"testing"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

func lire(s string) ([]uint64, []uint64, bool) {
	return parseVolontaires(bufio.NewScanner(strings.NewReader(s)))
}

// TestParseVolontaires couvre le format et, surtout, ce qu il ne doit PAS faire.
func TestParseVolontaires(t *testing.T) {
	pids, forces, ouvert := lire(`
# les 45 qui ne se connectent jamais
1800002540
!1800021392   # force pour la validation
1800000886

`)
	if ouvert {
		t.Fatal("aucun TOUS : ne doit pas elargir")
	}
	if len(pids) != 3 || pids[0] != 1800002540 || pids[2] != 1800000886 {
		t.Fatalf("pids=%v", pids)
	}
	if len(forces) != 1 || forces[0] != 1800021392 {
		t.Fatalf("forces=%v", forces)
	}
}

// TestParseListeVideNOuvrePas : le piege classique — une liste vide qui voudrait dire
// « tout le monde ». Ici elle veut dire « personne ».
func TestParseListeVideNOuvrePas(t *testing.T) {
	pids, forces, ouvert := lire("\n# rien\n\n")
	if ouvert || len(pids) != 0 || len(forces) != 0 {
		t.Fatalf("liste vide interpretee comme %v/%v/%v", pids, forces, ouvert)
	}
}

// TestParseLigneMalformeeEstIgnoree : jamais prise pour un joker.
func TestParseLigneMalformeeEstIgnoree(t *testing.T) {
	pids, _, ouvert := lire("abc\n*\n0\n1800000125\n")
	if ouvert {
		t.Fatal("une ligne malformee a ouvert le relais")
	}
	if len(pids) != 1 || pids[0] != 1800000125 {
		t.Fatalf("pids=%v, attendu seulement le PID valide", pids)
	}
}

// TestParseTousElargit : l elargissement doit etre explicite et lisible.
func TestParseTousElargit(t *testing.T) {
	_, _, ouvert := lire("1800000125\nTOUS\n")
	if !ouvert {
		t.Fatal("TOUS doit elargir")
	}
}

// TestAutoPreserveLesLignesManuelles : le serveur s ajoute des joueurs, mais le fichier doit
// rester editable a la main. Ecraser les lignes manuelles rendrait la liste inutilisable.
func TestAutoPreserveLesLignesManuelles(t *testing.T) {
	dir := t.TempDir()
	ancien := listePath
	listePath = dir + "/relay_allow"
	t.Cleanup(func() { listePath = ancien })

	manuel := "# ma liste\n1800000001\n!1800000002\n"
	if err := os.WriteFile(listePath, []byte(manuel), 0o644); err != nil {
		t.Fatal(err)
	}

	// Un joueur qui ne se connecte jamais.
	for i := 0; i < 12; i++ {
		nex.NotePercage(1800009999, false)
	}
	t.Cleanup(func() { nex.NotePercage(1800009999, true) })

	listeAutoEcrire()

	b, err := os.ReadFile(listePath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, "# ma liste") || !strings.Contains(got, "1800000001") ||
		!strings.Contains(got, "!1800000002") {
		t.Fatalf("lignes manuelles perdues:\n%s", got)
	}
	if !strings.Contains(got, "1800009999") {
		t.Fatalf("le candidat n a pas ete ajoute:\n%s", got)
	}

	// Et la liste ainsi ecrite doit se relire correctement.
	pids, forces, ouvert := lire(got)
	if ouvert {
		t.Fatal("le fichier genere ne doit jamais elargir a tous")
	}
	if len(pids) != 3 || len(forces) != 1 {
		t.Fatalf("relecture: pids=%v forces=%v", pids, forces)
	}
}

// TestAutoRetireCeluiQuiSeConnecte : la section automatique est REGENEREE, donc un joueur qui
// se met a se connecter en sort tout seul, sans intervention.
func TestAutoRetireCeluiQuiSeConnecte(t *testing.T) {
	dir := t.TempDir()
	ancien := listePath
	listePath = dir + "/relay_allow"
	t.Cleanup(func() { listePath = ancien })

	for i := 0; i < 12; i++ {
		nex.NotePercage(1800008888, false)
	}
	listeAutoEcrire()
	if b, _ := os.ReadFile(listePath); !strings.Contains(string(b), "1800008888") {
		t.Fatal("devait etre ajoute")
	}

	nex.NotePercage(1800008888, true)
	listeAutoEcrire()
	if b, _ := os.ReadFile(listePath); strings.Contains(string(b), "1800008888") {
		t.Fatalf("devait sortir apres une connexion reussie:\n%s", b)
	}
}
