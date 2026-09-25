package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReplacesTheFileAndLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	if err := Write(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "two" {
		t.Fatalf("read %q, %v; want the second write", got, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600: the store holds the attack map's triage", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("%d entries in the directory, want only the store: a temp file was left", len(entries))
	}
}

func TestWriteLeavesTheOldFileWhenItCannotFinish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	if err := Write(path, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(dir, "missing", "store.json"), []byte("x"), 0o600); err == nil {
		t.Fatal("writing into a missing directory succeeded")
	}
	if got, _ := os.ReadFile(path); string(got) != "kept" {
		t.Errorf("the existing store became %q", got)
	}
}
