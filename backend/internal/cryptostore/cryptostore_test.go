package cryptostore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// With encryption on, data the key did not seal is refused, not read: passing it through
// was what let anyone who could write to a store's file add a record nobody sealed - a
// suppression, say, that hides a path. What was written before the key is sealed once,
// explicitly (seal-stores), which IsSealed is for.
func TestOpenRefusesWhatTheKeyDidNotSeal(t *testing.T) {
	s, _ := New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	for _, plain := range [][]byte{
		[]byte(`{"legacy":true}`),
		[]byte(`{"records":[{"path_id":"ap-1","reason":"accepted risk"}]}`),
		[]byte("PGSEAL2\nnot ours"),
		[]byte("not json at all, and longer than the prefix"),
	} {
		out, err := s.Open(plain)
		if !errors.Is(err, ErrPlaintext) {
			t.Errorf("Open(%q) = %q, %v; want ErrPlaintext", plain, out, err)
		}
		if out != nil {
			t.Errorf("Open(%q) returned data alongside the refusal: %q", plain, out)
		}
		if IsSealed(plain) {
			t.Errorf("IsSealed(%q) = true", plain)
		}
	}

	sealed, err := s.Seal([]byte(`{"records":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(sealed) {
		t.Error("IsSealed is false for what Seal wrote")
	}
	// The passthrough sealer has nothing to refuse with: encryption off reads plaintext.
	if out, err := Nop().Open([]byte(`{"a":1}`)); err != nil || string(out) != `{"a":1}` {
		t.Errorf("Nop().Open = %q, %v", out, err)
	}
}

// A write torn inside the prefix leaves a sealed blob cut short, not plaintext, and must
// not be reported as one: the validation log drops a torn final record but reports a
// plaintext one, and it tells them apart by this error.
func TestABlobCutInsideThePrefixIsTornNotPlaintext(t *testing.T) {
	s, _ := New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	sealed, err := s.Seal([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n < len(magic); n++ {
		if _, err := s.Open(sealed[:n]); err == nil || errors.Is(err, ErrPlaintext) {
			t.Errorf("a sealed blob cut to %d byte(s): %v, want a too-short error that is not ErrPlaintext", n, err)
		}
	}
	// Cut after the prefix, it fails authentication - corrupt, never plaintext either.
	if _, err := s.Open(sealed[:len(sealed)-1]); err == nil || errors.Is(err, ErrPlaintext) {
		t.Errorf("a sealed blob missing its last byte: %v, want a decrypt error", err)
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
