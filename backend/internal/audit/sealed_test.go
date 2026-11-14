package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// With the key on, the log refuses a line the key did not seal: one that predates the key
// (a log not yet sealed by seal-stores) or one written since by someone who can write to
// the file but does not hold the key. The chain's hashes carry no key, so accepting
// plaintext let a log rewritten from its first line verify clean.
func TestALineTheKeyDidNotSealIsRefused(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	before := filepath.Join(t.TempDir(), "audit.log")
	plain, err := Open(before)
	if err != nil {
		t.Fatal(err)
	}
	plain.Record(ctx, "suppress.create", "tok", "admin", "acme", nil)
	plain.Record(ctx, "view.attack_paths", "tok", "viewer", "acme", nil)
	_ = plain.Close()
	if _, err := Open(before, WithSealer(sealer)); !errors.Is(err, cryptostore.ErrPlaintext) {
		t.Errorf("a log written before the key opened with it: %v, want ErrPlaintext", err)
	}
	if _, err := Verify(before, WithSealer(sealer)); !errors.Is(err, cryptostore.ErrPlaintext) {
		t.Errorf("a log written before the key verified with it: %v, want ErrPlaintext", err)
	}
	if n, err := Verify(before); err != nil || n != 2 {
		t.Errorf("without the key the plaintext log is what it was: %d records, %v", n, err)
	}

	// A record forged in plaintext behind sealed ones, chained correctly - what someone with
	// write access to the file and no key could add.
	sealed := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(sealed, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	l.Record(ctx, "view.attack_paths", "tok", "viewer", "acme", nil)
	_ = l.Close()
	seq, prev, err := tail(sealed, sealer)
	if err != nil {
		t.Fatal(err)
	}
	forged := Record{Seq: seq + 1, Time: time.Now().UTC(), Action: "suppress.delete", Subject: "tok", PrevHash: prev}
	forged.Hash = hashRecord(forged)
	line, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range [][]byte{line, []byte(base64.StdEncoding.EncodeToString(line))} {
		f, err := os.OpenFile(sealed, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(encoded, '\n')); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
		if n, err := Verify(sealed, WithSealer(sealer)); !errors.Is(err, cryptostore.ErrPlaintext) {
			t.Errorf("a forged line %.20q... verified: %d records, %v; want ErrPlaintext", encoded, n, err)
		}
		// Take it back out for the next encoding.
		b, err := os.ReadFile(sealed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sealed, b[:len(b)-len(encoded)-1], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := Verify(sealed, WithSealer(sealer)); err != nil || n != 1 {
		t.Errorf("the sealed log itself: %d records, %v; want 1", n, err)
	}
}

// SealFile seals a log written before the key, line by line, and the chain still
// verifies - with the key alone - because it runs over each record in plaintext. A log
// that does not verify is not sealed: that would certify it.
func TestSealFileSealsTheChainWithoutBreakingIt(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Two records before the key, then one after it: the log a key set mid-life leaves.
	path := filepath.Join(t.TempDir(), "audit.log")
	plain, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	plain.Record(ctx, "suppress.create", "tok", "admin", "acme", map[string]any{"path": "ap-1"})
	plain.Record(ctx, "view.attack_paths", "tok", "viewer", "acme", nil)
	_ = plain.Close()
	seq, prev, err := tail(path, cryptostore.Nop())
	if err != nil {
		t.Fatal(err)
	}
	third := Record{Seq: seq + 1, Time: time.Now().UTC(), Action: "export.oscal", Subject: "tok", PrevHash: prev}
	third.Hash = hashRecord(third)
	line, _ := json.Marshal(third)
	sealedLine, err := encodeLine(line, sealer)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(sealedLine, '\n')); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	before, _ := os.ReadFile(path)
	if r, err := SealFile(path, sealer, true); err != nil || r.Plain != 2 || r.Sealed != 1 {
		t.Fatalf("dry run: %+v, %v; want 2 plain, 1 sealed", r, err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(before) {
		t.Fatal("a dry run wrote to the log")
	}
	if r, err := SealFile(path, sealer, false); err != nil || r.Plain != 2 || r.Sealed != 1 {
		t.Fatalf("seal: %+v, %v", r, err)
	}
	if n, err := Verify(path, WithSealer(sealer)); err != nil || n != 3 {
		t.Fatalf("the sealed chain: %d records, %v; want 3 verified with the key", n, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "suppress.create") {
		t.Error("a record is still in plaintext on disk")
	}
	// The engine resumes it.
	resumed, err := Open(path, WithSealer(sealer))
	if err != nil {
		t.Fatalf("the engine cannot resume the sealed log: %v", err)
	}
	resumed.Record(ctx, "api", "tok", "admin", "acme", nil)
	_ = resumed.Close()
	if n, err := Verify(path, WithSealer(sealer)); err != nil || n != 4 {
		t.Fatalf("the resumed chain: %d records, %v; want 4", n, err)
	}

	// A plaintext log whose chain is broken is left exactly as it is.
	broken := filepath.Join(t.TempDir(), "audit.log")
	b, err := Open(broken)
	if err != nil {
		t.Fatal(err)
	}
	b.Record(ctx, "suppress.create", "tok", "admin", "acme", nil)
	b.Record(ctx, "suppress.delete", "tok", "admin", "acme", nil)
	_ = b.Close()
	content, _ := os.ReadFile(broken)
	tampered := strings.Replace(string(content), "suppress.delete", "suppress.update", 1)
	if err := os.WriteFile(broken, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SealFile(broken, sealer, false); err == nil {
		t.Fatal("a log whose chain does not verify was sealed")
	}
	if got, _ := os.ReadFile(broken); string(got) != tampered {
		t.Error("a refused log was rewritten")
	}
}

// What SealFile will not seal, and says why: a line that is neither a record nor sealed
// (no engine writes base64 around plaintext), a line it cannot decode, and anything at all
// without a key. A log that is not there has nothing to seal.
func TestSealFileRefusesWhatTheEngineNeverWrote(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if r, err := SealFile(filepath.Join(t.TempDir(), "absent.log"), sealer, false); err != nil || !r.Absent {
		t.Errorf("a missing log: %+v, %v; want Absent", r, err)
	}
	for name, line := range map[string]string{
		"base64 around plaintext": base64.StdEncoding.EncodeToString([]byte(`{"seq":1}`)),
		"undecodable":             "not base64 !",
	} {
		path := filepath.Join(t.TempDir(), "audit.log")
		if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := SealFile(path, sealer, false); err == nil {
			t.Errorf("%s: sealed a line the engine never wrote", name)
		}
		if got, _ := os.ReadFile(path); string(got) != line+"\n" {
			t.Errorf("%s: a refused log was rewritten", name)
		}
	}
	if _, err := SealFile(filepath.Join(t.TempDir(), "audit.log"), cryptostore.Nop(), false); err == nil {
		t.Error("sealed without a key")
	}
}

// SealPG does the same for the chain in the database: the fields written before the key
// are sealed in place, and the chain verifies with the key alone.
func TestSealPGSealsTheFieldsWrittenBeforeTheKey(t *testing.T) {
	plain, db := pgLog(t)
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	plain.Record(ctx, "auth.deny", "mallory", "", "acme", map[string]any{"remote": "203.0.113.9"})
	plain.Record(ctx, "view.attack_paths", "tok", "viewer", "acme", nil)
	settled(t, plain)
	keyed, err := OpenPG(db, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	keyed.Record(ctx, "export.oscal", "tok", "admin", "acme", map[string]any{"format": "oscal"})
	settled(t, keyed)

	if _, err := VerifyPG(ctx, db, WithSealer(sealer)); !errors.Is(err, cryptostore.ErrPlaintext) {
		t.Fatalf("a chain with fields written before the key verified with it: %v, want ErrPlaintext", err)
	}
	if r, err := SealPG(ctx, db, sealer, true); err != nil || r.Plain != 2 || r.Sealed != 1 {
		t.Fatalf("dry run: %+v, %v; want 2 plain, 1 sealed", r, err)
	}
	if _, err := VerifyPG(ctx, db, WithSealer(sealer)); !errors.Is(err, cryptostore.ErrPlaintext) {
		t.Fatalf("a dry run sealed something: %v", err)
	}
	if r, err := SealPG(ctx, db, sealer, false); err != nil || r.Plain != 2 {
		t.Fatalf("seal: %+v, %v", r, err)
	}
	if n, err := VerifyPG(ctx, db, WithSealer(sealer)); err != nil || n != 3 {
		t.Fatalf("the sealed chain: %d records, %v; want 3 verified with the key", n, err)
	}
	var raw string
	if err := db.QueryRow(`SELECT string_agg(fields::text, ' ') FROM audit_log`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "203.0.113.9") {
		t.Errorf("the remote address is still in clear: %s", raw)
	}

	// A chain altered in the database is left as it is.
	if _, err := db.Exec(`UPDATE audit_log SET subject = 'eve' WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := SealPG(ctx, db, sealer, false); err == nil {
		t.Error("a chain that does not verify was sealed")
	}
}

// In the database only the fields are sealed. Fields written before the key are a JSON
// object rather than the sealed string, and a string carrying plaintext has the sealed
// shape but not the seal: both are refused as plaintext, so verify-audit points at
// seal-stores rather than at a parse error.
func TestFieldsTheKeyDidNotSealAreRefused(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	object := []byte(`{"format":"oscal"}`)
	wrapped, err := json.Marshal(base64.StdEncoding.EncodeToString(object))
	if err != nil {
		t.Fatal(err)
	}
	for _, fields := range [][]byte{object, wrapped, []byte("null"), nil} {
		if out, err := openFields(fields, sealer); !errors.Is(err, cryptostore.ErrPlaintext) {
			t.Errorf("openFields(%s) = %q, %v; want ErrPlaintext", fields, out, err)
		}
	}
	if out, err := openFields(object, cryptostore.Nop()); err != nil || string(out) != string(object) {
		t.Errorf("with the key off the fields read as written: %q, %v", out, err)
	}
}
