// Package cryptostore provides at-rest encryption for the file-backed governance
// stores (suppressions, tickets, validations, history) and the audit log. The
// tool's persisted state IS a map of how to attack the org plus who has viewed
// it, so a stolen volume or backup shouldn't hand that over in plaintext.
//
// A nil/Nop sealer is passthrough (encryption disabled - the default). The AEAD
// sealer uses AES-256-GCM with a random per-record nonce, and sealed blobs carry a
// magic prefix. With encryption on, Open refuses data without it (ErrPlaintext): it used
// to pass such data through, so that stores written before the key was set stayed
// readable, and that same rule let anyone who could write to the storage add a record
// the key never sealed. Data written before the key is sealed once, explicitly, by
// `perspectivegraph seal-stores` or STORE_SEAL_EXISTING.
package cryptostore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// magic marks a sealed blob. Plaintext JSON never starts with it, so Open can
// tell encrypted and pre-encryption data apart.
var magic = []byte("PGSEAL1\n")

// ErrPlaintext is what Open returns, with encryption on, for data that is not sealed:
// written before STORE_ENCRYPTION_KEY was set, or by someone who does not hold it. The
// key is what makes a record trustworthy - AES-GCM authenticates what it decrypts - so
// data that skipped it is refused rather than read. A suppression slipped into the
// store's file would otherwise hide an attack path, and an audit chain rewritten in
// plaintext would verify, its hashes being unkeyed.
var ErrPlaintext = errors.New("cryptostore: data is not sealed with STORE_ENCRYPTION_KEY - it was written " +
	"before the key was set, or by someone who does not hold it")

// IsSealed reports whether blob is a sealed blob: one that starts with the prefix Seal
// writes. It says nothing about whether the key at hand opens it.
func IsSealed(blob []byte) bool { return bytes.HasPrefix(blob, magic) }

// Sealer encrypts/decrypts at rest. Implementations are safe for concurrent use.
type Sealer interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(blob []byte) ([]byte, error)
	Enabled() bool
}

type nopSealer struct{}

func (nopSealer) Seal(b []byte) ([]byte, error) { return b, nil }
func (nopSealer) Open(b []byte) ([]byte, error) { return b, nil }
func (nopSealer) Enabled() bool                 { return false }

// Nop is the passthrough sealer (encryption disabled).
func Nop() Sealer { return nopSealer{} }

type aeadSealer struct{ gcm cipher.AEAD }

// IsPassphrase reports whether key is a passphrase rather than a raw key: anything but
// 64 hex characters. New turns a passphrase into the key with a single SHA-256, so an
// attacker holding an encrypted backup can test guesses at hashing speed - which is why a
// production deployment refuses one.
func IsPassphrase(key string) bool {
	if key == "" {
		return false
	}
	b, err := hex.DecodeString(key)
	return err != nil || len(b) != 32
}

// New returns an AES-256-GCM sealer derived from key, or the Nop sealer when key
// is empty. A 64-hex-char key is used as the raw 32-byte key; any other non-empty
// value is treated as a passphrase and stretched to 32 bytes with SHA-256.
func New(key string) (Sealer, error) {
	if key == "" {
		return Nop(), nil
	}
	var k []byte
	if b, err := hex.DecodeString(key); err == nil && len(b) == 32 {
		k = b
	} else {
		sum := sha256.Sum256([]byte(key))
		k = sum[:]
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("cryptostore: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptostore: gcm: %w", err)
	}
	return &aeadSealer{gcm: gcm}, nil
}

func (s *aeadSealer) Enabled() bool { return true }

func (s *aeadSealer) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := s.gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(magic)+len(nonce)+len(ct))
	out = append(out, magic...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func (s *aeadSealer) Open(blob []byte) ([]byte, error) {
	if !bytes.HasPrefix(blob, magic) {
		// Cut off inside the prefix, a blob is a sealed one that was truncated - a write
		// torn by a crash - not plaintext. Callers that tolerate a torn final record tell
		// the two apart by this, so that a record the key never sealed is reported rather
		// than dropped as torn.
		if len(blob) < len(magic) && bytes.HasPrefix(magic, blob) {
			return nil, errors.New("cryptostore: sealed blob too short")
		}
		return nil, ErrPlaintext
	}
	blob = blob[len(magic):]
	ns := s.gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("cryptostore: sealed blob too short")
	}
	nonce, ct := blob[:ns], blob[ns:]
	pt, err := s.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("cryptostore: decrypt (wrong key or corrupt data): %w", err)
	}
	return pt, nil
}
