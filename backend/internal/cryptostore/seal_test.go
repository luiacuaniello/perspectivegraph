package cryptostore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SealFile is the explicit migration that replaced Open's passthrough: what was written
// before the key is sealed once, on purpose, and from then on plaintext is refused.
func TestSealFileSealsWhatPredatesTheKeyAndOnlyThat(t *testing.T) {
	s, err := New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if r, err := SealFile(filepath.Join(dir, "absent.json"), s, false); err != nil || !r.Absent {
		t.Errorf("a missing store: %+v, %v; want Absent", r, err)
	}
	if r, err := SealFile(write("empty.json", nil), s, false); err != nil || !r.Absent {
		t.Errorf("an empty store: %+v, %v; want Absent", r, err)
	}

	plain := []byte(`{"records":[{"path_id":"ap-1","reason":"accepted risk"}]}`)
	p := write("suppressions.json", plain)
	if r, err := SealFile(p, s, true); err != nil || r.Plain != 1 {
		t.Fatalf("dry run: %+v, %v; want one plaintext record", r, err)
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, plain) {
		t.Fatal("a dry run wrote to the store")
	}
	if r, err := SealFile(p, s, false); err != nil || r.Plain != 1 {
		t.Fatalf("seal: %+v, %v", r, err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(got) || bytes.Contains(got, []byte("ap-1")) {
		t.Fatalf("the store is not sealed on disk: %q", got)
	}
	if opened, err := s.Open(got); err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("the sealed store does not open to what it held: %q, %v", opened, err)
	}
	if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the sealed store is not owner-only: %v, %v", info.Mode(), err)
	}

	// Sealing again finds it sealed and leaves it alone.
	if r, err := SealFile(p, s, false); err != nil || r.Sealed != 1 || r.Plain != 0 {
		t.Errorf("a sealed store: %+v, %v; want Sealed 1", r, err)
	}
	if again, _ := os.ReadFile(p); !bytes.Equal(again, got) {
		t.Error("sealing a sealed store rewrote it")
	}

	// A store sealed with another key is not this key's to vouch for.
	other, _ := New(strings.Repeat("cd", 32))
	if _, err := SealFile(p, other, false); err == nil {
		t.Error("a store sealed with another key passed as sealed")
	}
	// Neither sealed nor JSON: reported, never wrapped.
	junk := write("junk.json", []byte("this is not a store"))
	if _, err := SealFile(junk, s, false); err == nil {
		t.Error("a file that is neither sealed nor JSON was sealed")
	}
	if got, _ := os.ReadFile(junk); string(got) != "this is not a store" {
		t.Error("a refused file was rewritten")
	}
	if _, err := SealFile(p, Nop(), false); err == nil {
		t.Error("sealing without a key succeeded")
	}
}
