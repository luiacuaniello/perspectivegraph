package exportsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestDisabledWhenNoSeed(t *testing.T) {
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled() {
		t.Fatal("empty seed must disable signing")
	}
	if s.Sign([]byte("x")) != "" || s.PublicKeyB64() != "" {
		t.Fatal("disabled signer must return empty strings")
	}
}

func TestSignVerifies(t *testing.T) {
	seed := strings.Repeat("ab", 32) // 64 hex chars = 32-byte seed
	s, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enabled() {
		t.Fatal("valid seed must enable signing")
	}

	body := []byte(`{"@schema":"perspectivegraph.enrichment.v1"}`)
	hdr := s.Sign(body)
	rawSig, ok := strings.CutPrefix(hdr, "ed25519=")
	if !ok {
		t.Fatalf("unexpected header format: %q", hdr)
	}
	sig, err := base64.StdEncoding.DecodeString(rawSig)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(s.PublicKeyB64())
	if err != nil {
		t.Fatal(err)
	}

	// A consumer with the public key verifies the export.
	if !ed25519.Verify(pub, body, sig) {
		t.Fatal("signature did not verify against the published public key")
	}
	// Tampering is detected.
	if ed25519.Verify(pub, []byte(`{"tampered":true}`), sig) {
		t.Fatal("signature verified against tampered body")
	}
}

func TestBadSeedRejected(t *testing.T) {
	for _, bad := range []string{"xyz", "abcd", strings.Repeat("a", 63)} {
		if _, err := New(bad); err == nil {
			t.Errorf("expected error for bad seed %q", bad)
		}
	}
}
