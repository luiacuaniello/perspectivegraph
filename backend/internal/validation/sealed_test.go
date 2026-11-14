package validation

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// A log written before the key - the append-only format, and the single blob before it -
// is sealed once by SealFile, and then opens with the key and nothing else.
func TestSealFileSealsALogWrittenBeforeTheKey(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	logPath := filepath.Join(t.TempDir(), "v.log")
	plain, err := New(logPath)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, plain, 3)
	before, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := SealFile(logPath, sealer, true); err != nil || r.Plain != 3 {
		t.Fatalf("dry run: %+v, %v; want 3 plaintext records", r, err)
	}
	if got, _ := os.ReadFile(logPath); string(got) != string(before) {
		t.Fatal("a dry run wrote to the log")
	}
	if r, err := SealFile(logPath, sealer, false); err != nil || r.Plain != 3 || r.Sealed != 0 {
		t.Fatalf("seal: %+v, %v", r, err)
	}
	reloaded, err := New(logPath, WithSealer(sealer))
	if err != nil {
		t.Fatalf("the sealed log does not open with the key: %v", err)
	}
	if got := lenOf(reloaded.List(ctx, "acme")); got != 3 {
		t.Fatalf("the sealed log holds %d records, want 3", got)
	}
	if _, err := New(logPath); err == nil {
		t.Error("the sealed log opened without the key")
	}
	// Records written since are sealed already: sealing again finds nothing to do.
	seed(t, reloaded, 1)
	if r, err := SealFile(logPath, sealer, false); err != nil || r.Plain != 0 || r.Sealed != 4 {
		t.Errorf("sealing a sealed log: %+v, %v; want 4 sealed, none plain", r, err)
	}

	// The format before the log: one JSON blob.
	blobPath := filepath.Join(t.TempDir(), "v.json")
	if err := os.WriteFile(blobPath, []byte(`{"records":[{"id":"r1","path_id":"p","outcome":"missed","source":"s","tenant":"acme"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if r, err := SealFile(blobPath, sealer, false); err != nil || r.Plain != 1 {
		t.Fatalf("seal a blob store: %+v, %v", r, err)
	}
	blob, err := New(blobPath, WithSealer(sealer))
	if err != nil {
		t.Fatalf("the sealed blob store does not open with the key: %v", err)
	}
	if got := lenOf(blob.List(ctx, "acme")); got != 1 {
		t.Fatalf("the sealed blob store holds %d records, want 1", got)
	}
}

// Before the last line nothing is torn: a line that is neither sealed nor a record, or one
// sealed with another key, is reported and the log left as it was. Without a key there is
// nothing to seal with.
func TestSealFileReportsALogItCannotVouchFor(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := cryptostore.New(strings.Repeat("ff", 32))
	foreign, err := other.Seal([]byte(`{"op":"del","tenant":"acme","id":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, middle := range map[string]string{
		"corrupt":            "!!not a line!!",
		"another key's":      base64.StdEncoding.EncodeToString(foreign),
		"not json, unsealed": base64.StdEncoding.EncodeToString([]byte("plain text, not a record")),
	} {
		path := filepath.Join(t.TempDir(), "v.log")
		plain, err := New(path)
		if err != nil {
			t.Fatal(err)
		}
		seed(t, plain, 1)
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(middle + "\n"); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		seed(t, plain, 1) // a record after it, so the bad line is not the last
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := SealFile(path, sealer, false); err == nil {
			t.Errorf("%s line in the middle: sealed anyway", name)
		}
		if got, _ := os.ReadFile(path); string(got) != string(before) {
			t.Errorf("%s line in the middle: the log was rewritten", name)
		}
	}
	if _, err := SealFile(filepath.Join(t.TempDir(), "v.log"), cryptostore.Nop(), false); err == nil {
		t.Error("sealed without a key")
	}
}

// A torn final line is handled by what it was. A plaintext one is dropped - kept, it would
// be the plaintext record the key refuses, and the store would not open - while a sealed
// one that does not open is kept as it was, since nothing proves this key wrote it.
func TestSealFileDropsATornPlaintextTailAndKeepsASealedOne(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v.log")
	plain, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, plain, 2)
	appendLine := func(line string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	appendLine("eyJvcCI6InB1dCIsInJlYyI6ey") // base64 of a plaintext event cut short

	r, err := SealFile(path, sealer, false)
	if err != nil || r.Plain != 2 || r.Torn != 1 {
		t.Fatalf("a torn plaintext tail: %+v, %v; want 2 sealed, 1 torn", r, err)
	}
	reloaded, err := New(path, WithSealer(sealer))
	if err != nil {
		t.Fatalf("the store does not open after its torn plaintext tail was dropped: %v", err)
	}
	if got := lenOf(reloaded.List(context.Background(), "acme")); got != 2 {
		t.Fatalf("%d records, want 2", got)
	}

	// A sealed line that does not open, at the end: kept byte for byte.
	other, _ := cryptostore.New(strings.Repeat("ff", 32))
	foreign, err := other.Seal([]byte(`{"op":"del","tenant":"acme","id":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	foreignLine := base64.StdEncoding.EncodeToString(foreign)
	appendLine(foreignLine)
	if r, err := SealFile(path, sealer, false); err != nil || r.Torn != 1 {
		t.Fatalf("a sealed tail this key does not open: %+v, %v; want it counted as torn", r, err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(got), foreignLine+"\n") {
		t.Error("a sealed line this key does not open was not kept as it was")
	}
}

// A record the key did not seal is reported wherever it sits in the log, the last line
// included. The torn-tail rule drops a final record cut short by a crash; a record in
// plaintext is not one. With a single record - so that it IS the last line - a log written
// before the key loaded as an empty store, and the next verdict was appended behind the
// line nobody had sealed.
func TestARecordTheKeyDidNotSealIsNotATornTail(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}

	before := filepath.Join(t.TempDir(), "v.log")
	plain, err := New(before)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, plain, 1)
	if _, err := New(before, WithSealer(sealer)); !errors.Is(err, cryptostore.ErrPlaintext) {
		t.Fatalf("a one-record log written before the key opened with it: %v, want ErrPlaintext", err)
	}

	// The rule the tolerance exists for still holds: a sealed log whose final line was
	// torn by a crash loads every record before it. Cut inside the sealed prefix, that
	// line decodes to a few bytes of it, which is neither plaintext nor a record.
	sealedPath := filepath.Join(t.TempDir(), "v.log")
	s, err := New(sealedPath, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s, 2)
	for _, torn := range []string{"UEdTRUFM\n", "UEdTRU\n"} { // base64 of "PGSEAL", and a cut mid-quantum
		f, err := os.OpenFile(sealedPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(torn); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		reloaded, err := New(sealedPath, WithSealer(sealer))
		if err != nil {
			t.Fatalf("a sealed log with a torn final line %q did not load: %v", torn, err)
		}
		if got := lenOf(reloaded.List(context.Background(), "acme")); got != 2 {
			t.Fatalf("torn final line %q: %d records, want 2", torn, got)
		}
		// Put the file back to two clean lines for the next case.
		b, err := os.ReadFile(sealedPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sealedPath, b[:len(b)-len(torn)], 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
