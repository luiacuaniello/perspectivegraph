package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/luiacuaniello/perspectivegraph/internal/reqid"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

func TestEncryptedAuditAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sealer, _ := cryptostore.New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	log, err := Open(path, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	log.Record(context.Background(), "export.oscal", "tok-abc", "admin", "acme", map[string]any{"format": "oscal"})
	log.Record(context.Background(), "view.attack_paths", "tok-abc", "viewer", "acme", map[string]any{"count": 13})
	_ = log.Close()

	// On disk the actions/fields must be encrypted, not plaintext JSON.
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("view.attack_paths")) || bytes.Contains(raw, []byte("oscal")) {
		t.Fatal("audit record leaked in plaintext on disk")
	}

	// Verify with the key passes (the hash chain runs over plaintext records).
	if n, err := Verify(path, WithSealer(sealer)); err != nil || n != 2 {
		t.Fatalf("encrypted verify: n=%d err=%v, want 2/nil", n, err)
	}

	// Resuming an encrypted log continues the chain.
	log2, err := Open(path, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	log2.Record(context.Background(), "api", "tok-xyz", "admin", "acme", nil)
	_ = log2.Close()
	if n, err := Verify(path, WithSealer(sealer)); err != nil || n != 3 {
		t.Fatalf("resumed encrypted log: n=%d err=%v, want 3/nil", n, err)
	}

	// Verify WITHOUT the key cannot read the encrypted lines.
	if _, err := Verify(path); err == nil {
		t.Fatal("verify without the key should fail on encrypted lines")
	}
}

func TestHashChainVerifiesAndDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	log.Record(context.Background(), "api", "tok-abc", "viewer", "acme", map[string]any{"path": "/graphql"})
	log.Record(context.Background(), "ingest", "hmac", "", "acme", map[string]any{"source": "trivy"})
	log.Record(context.Background(), "api", "tok-xyz", "admin", "globex", nil)
	_ = log.Close()

	// Intact chain verifies.
	n, err := Verify(path)
	if err != nil {
		t.Fatalf("intact log failed verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d records, want 3", n)
	}

	// Resuming continues the chain (no break).
	log2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	log2.Record(context.Background(), "api", "tok-abc", "viewer", "acme", nil)
	_ = log2.Close()
	if n, err := Verify(path); err != nil || n != 4 {
		t.Fatalf("resumed log: n=%d err=%v, want 4/nil", n, err)
	}

	// Tamper with the middle record's payload → verification must catch it.
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], `"trivy"`, `"semgrep"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); err == nil {
		t.Fatal("tampered log passed verification - chain is not tamper-evident")
	}
}

func TestVerifyMissingFileIsClean(t *testing.T) {
	if n, err := Verify(filepath.Join(t.TempDir(), "nope.log")); err != nil || n != 0 {
		t.Fatalf("missing file: n=%d err=%v, want 0/nil", n, err)
	}
}

// The audit log is the forensic artefact, so it is where correlation matters most: an
// entry saying "this principal opened a PR" is far more useful when it can be joined to
// the HTTP call and the log lines that came with it.
func TestRecordCarriesTheRequestID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := reqid.NewContext(context.Background(), "req-abc123")
	log.Record(ctx, "api", "alice", "admin", "acme", map[string]any{"path": "/graphql"})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec Record
	if err := json.Unmarshal(b[:len(b)-1], &rec); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := rec.Fields["request_id"]; got != "req-abc123" {
		t.Errorf("request_id = %v, want req-abc123", got)
	}
	if got := rec.Fields["path"]; got != "/graphql" {
		t.Errorf("the caller's own fields were lost: %v", rec.Fields)
	}
	// The chain must still verify: the id rides in Fields precisely so the hashed
	// shape of a Record does not change.
	if n, err := Verify(path); err != nil || n != 1 {
		t.Errorf("chain broke after adding a request id: n=%d err=%v", n, err)
	}
}

// Without a request id the record must be exactly what this log has always written -
// no empty key, nothing for a verifier to trip on.
func TestRecordWithoutRequestIDIsUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	log.Record(context.Background(), "api", "bob", "viewer", "acme", map[string]any{"path": "/x"})
	_ = log.Close()

	b, _ := os.ReadFile(path)
	var rec Record
	if err := json.Unmarshal(b[:len(b)-1], &rec); err != nil {
		t.Fatal(err)
	}
	if _, present := rec.Fields["request_id"]; present {
		t.Errorf("a record with no request context carries a request_id: %v", rec.Fields)
	}
	if n, err := Verify(path); err != nil || n != 1 {
		t.Errorf("chain invalid: n=%d err=%v", n, err)
	}
}

// The caller's map must not be mutated - it may be shared or reused, and writing to it
// under the log's lock while a caller reads it outside is a data race.
func TestRecordDoesNotMutateTheCallersFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	fields := map[string]any{"path": "/graphql"}
	log.Record(reqid.NewContext(context.Background(), "req-xyz"), "api", "alice", "admin", "acme", fields)

	if _, leaked := fields["request_id"]; leaked {
		t.Error("Record wrote request_id into the caller's own map")
	}
}
