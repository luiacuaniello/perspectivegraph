package audit

import (
	"bytes"
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
	log.Record("export.oscal", "tok-abc", "admin", "acme", map[string]any{"format": "oscal"})
	log.Record("view.attack_paths", "tok-abc", "viewer", "acme", map[string]any{"count": 13})
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
	log2.Record("api", "tok-xyz", "admin", "acme", nil)
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
	log.Record("api", "tok-abc", "viewer", "acme", map[string]any{"path": "/graphql"})
	log.Record("ingest", "hmac", "", "acme", map[string]any{"source": "trivy"})
	log.Record("api", "tok-xyz", "admin", "globex", nil)
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
	log2.Record("api", "tok-abc", "viewer", "acme", nil)
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
		t.Fatal("tampered log passed verification — chain is not tamper-evident")
	}
}

func TestVerifyMissingFileIsClean(t *testing.T) {
	if n, err := Verify(filepath.Join(t.TempDir(), "nope.log")); err != nil || n != 0 {
		t.Fatalf("missing file: n=%d err=%v, want 0/nil", n, err)
	}
}
