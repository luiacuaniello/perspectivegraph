package cryptostore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNopIsPassthrough(t *testing.T) {
	s := Nop()
	if s.Enabled() {
		t.Fatal("Nop must report disabled")
	}
	in := []byte(`{"a":1}`)
	sealed, _ := s.Seal(in)
	if !bytes.Equal(sealed, in) {
		t.Fatal("Nop.Seal must passthrough")
	}
	out, _ := s.Open(sealed)
	if !bytes.Equal(out, in) {
		t.Fatal("Nop.Open must passthrough")
	}
}

func TestAEADRoundTrip(t *testing.T) {
	s, err := New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enabled() {
		t.Fatal("AEAD must report enabled")
	}
	in := []byte(`{"suppressions":[{"path_id":"ap-1"}]}`)
	sealed, err := s.Seal(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("ap-1")) {
		t.Fatal("ciphertext leaks plaintext")
	}
	if !bytes.HasPrefix(sealed, magic) {
		t.Fatal("sealed blob missing magic prefix")
	}
	out, err := s.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("round-trip mismatch: %q", out)
	}
	// Two seals of the same plaintext differ (random nonce).
	again, _ := s.Seal(in)
	if bytes.Equal(again, sealed) {
		t.Fatal("nonce reuse: identical ciphertexts")
	}
}

func TestPassphraseDerivation(t *testing.T) {
	// A non-hex value is accepted as a passphrase.
	s, err := New("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	in := []byte("secret")
	sealed, _ := s.Seal(in)
	out, _ := s.Open(sealed)
	if !bytes.Equal(out, in) {
		t.Fatal("passphrase round-trip failed")
	}
}

func TestOpenReadsPreEncryptionPlaintext(t *testing.T) {
	// Enabling encryption must still read files written before it was on.
	s, _ := New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	plain := []byte(`{"legacy":true}`)
	out, err := s.Open(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("must passthrough non-magic (plaintext) data for migration")
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, _ := New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	b, _ := New("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	sealed, _ := a.Seal([]byte("data"))
	if _, err := b.Open(sealed); err == nil {
		t.Fatal("Open with the wrong key must fail")
	}
}

// A production deployment refuses a passphrase, and the way out it offers has to keep what
// is already encrypted readable: the SHA-256 of the passphrase, written as 64 hex
// characters, is the same key - so a store sealed under the passphrase opens under it.
func TestThePassphrasesHashOpensWhatThePassphraseSealed(t *testing.T) {
	const pass = "correct horse battery staple"
	sum := sha256.Sum256([]byte(pass))
	hexKey := hex.EncodeToString(sum[:])

	for key, want := range map[string]bool{
		"":                      false,
		pass:                    true,
		hexKey:                  false,
		strings.ToUpper(hexKey): false,
		hexKey[:63]:             true,
		hexKey + "00":           true,
		strings.Repeat("z", 64): true,
		hexKey[:62] + "\n":      true,
	} {
		if got := IsPassphrase(key); got != want {
			t.Errorf("IsPassphrase(%q) = %v, want %v", key, got, want)
		}
	}

	byPass, err := New(pass)
	if err != nil {
		t.Fatal(err)
	}
	in := []byte(`{"suppressions":[]}`)
	sealed, err := byPass.Seal(in)
	if err != nil {
		t.Fatal(err)
	}
	byHex, err := New(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := byHex.Open(sealed); err != nil || !bytes.Equal(out, in) {
		t.Fatalf("the passphrase's SHA-256 as a hex key did not open what the passphrase sealed: %q, %v", out, err)
	}
}
