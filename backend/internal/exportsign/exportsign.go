// Package exportsign produces detached Ed25519 signatures over the tool's
// exports (OSCAL assessment-results, SIEM NDJSON). The exports leave the trust
// boundary - a GRC auditor or a SIEM ingests them - so a consumer needs to verify
// they really came from this engine and weren't altered in transit or at rest.
// Asymmetric signing means the verifier holds only the public key, never a secret
// it could forge with.
package exportsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Signer signs export bodies. A nil *Signer is valid and means "signing
// disabled" - Sign returns "" and Enabled reports false.
type Signer struct {
	priv ed25519.PrivateKey
	pub  string // base64-encoded public key
}

// New builds a Signer from a 64-hex-char Ed25519 seed, or nil when seed is empty
// (signing disabled).
func New(seed string) (*Signer, error) {
	if seed == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(seed)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("exportsign: EXPORT_SIGNING_KEY must be %d bytes as hex (a valid 64-char hex seed)", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(b)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &Signer{priv: priv, pub: base64.StdEncoding.EncodeToString(pub)}, nil
}

// Enabled reports whether signing is configured.
func (s *Signer) Enabled() bool { return s != nil }

// Sign returns the detached-signature header value ("ed25519=<base64>") for body,
// or "" when signing is disabled.
func (s *Signer) Sign(body []byte) string {
	if s == nil {
		return ""
	}
	return "ed25519=" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, body))
}

// PublicKeyB64 returns the base64 Ed25519 public key consumers verify with, or
// "" when signing is disabled.
func (s *Signer) PublicKeyB64() string {
	if s == nil {
		return ""
	}
	return s.pub
}
