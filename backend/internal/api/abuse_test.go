package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
)

// A2: a signed export carries a detached Ed25519 signature a consumer verifies
// with the published public key.
func TestExportIsSignedAndVerifiable(t *testing.T) {
	a, _ := testAPI(t)
	signer, err := exportsign.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	a.WithExportSigner(signer)

	rw := httptest.NewRecorder()
	a.exportOSCAL(rw, httptest.NewRequest("GET", "/export/oscal", nil).WithContext(viewerCtx()))

	hdr := rw.Header().Get("X-PerspectiveGraph-Signature")
	rawSig, ok := strings.CutPrefix(hdr, "ed25519=")
	if !ok {
		t.Fatalf("missing/unexpected signature header: %q", hdr)
	}
	sig, _ := base64.StdEncoding.DecodeString(rawSig)
	pub, _ := base64.StdEncoding.DecodeString(rw.Header().Get("X-PerspectiveGraph-PublicKey"))
	if !ed25519.Verify(pub, rw.Body.Bytes(), sig) {
		t.Fatal("export body does not verify against the published public key")
	}
	// Tampering with the body breaks verification.
	if ed25519.Verify(pub, append(rw.Body.Bytes(), '!'), sig) {
		t.Fatal("signature verified a tampered body")
	}
}

// Unsigned export (no signer) carries no signature header.
func TestExportUnsignedByDefault(t *testing.T) {
	a, _ := testAPI(t)
	rw := httptest.NewRecorder()
	a.exportOSCAL(rw, httptest.NewRequest("GET", "/export/oscal", nil).WithContext(viewerCtx()))
	if h := rw.Header().Get("X-PerspectiveGraph-Signature"); h != "" {
		t.Fatalf("unsigned export should have no signature header, got %q", h)
	}
}

// A3: a bulk read/export of the attack map by one principal fires one
// exfiltration alert (then stays quiet during cooldown).
func TestExfilAlertFiresOnBulkRead(t *testing.T) {
	a, _ := testAPI(t)
	fired := 0
	exfil := secwatch.New(10, time.Minute, time.Minute, func(string, int) { fired++ })
	a.WithAbuseWatchers(exfil, nil)

	// One view of 25 paths crosses the threshold of 10.
	a.auditView(viewerCtx(), "view.attack_paths", map[string]any{"count": 25})
	if fired != 1 {
		t.Fatalf("exfil alert fired %d times, want 1", fired)
	}
	// A subsequent small view does not re-alert during cooldown.
	a.auditView(viewerCtx(), "view.attack_paths", map[string]any{"count": 1})
	if fired != 1 {
		t.Fatalf("exfil re-alerted during cooldown: fired=%d", fired)
	}
}
