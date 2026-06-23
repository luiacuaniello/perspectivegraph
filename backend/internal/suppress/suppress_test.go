package suppress

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

func TestEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suppressions.json")
	sealer, _ := cryptostore.New("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	s, err := New(path, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(Record{PathID: "ap-secret", Owner: "secops", Reason: ReasonAcceptRisk}); err != nil {
		t.Fatal(err)
	}

	// On disk it must NOT be readable plaintext.
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("ap-secret")) {
		t.Fatal("suppression leaked in plaintext on disk")
	}

	// Reopen with the same key → decrypts and the decision survives.
	s2, err := New(path, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get("default", "ap-secret"); !ok {
		t.Fatal("encrypted record did not survive reload")
	}

	// Reopen with the WRONG key → hard error, never a silent plaintext fallback.
	wrong, _ := cryptostore.New("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if _, err := New(path, WithSealer(wrong)); err == nil {
		t.Fatal("expected decryption failure with the wrong key")
	}
}

func TestPutValidation(t *testing.T) {
	s, _ := New("")
	cases := []struct {
		name string
		rec  Record
		want error
	}{
		{"missing path", Record{Owner: "alice", Reason: ReasonAcceptRisk}, ErrMissingPathID},
		{"missing owner", Record{PathID: "ap-1", Reason: ReasonAcceptRisk}, ErrMissingOwner},
		{"bad reason", Record{PathID: "ap-1", Owner: "alice", Reason: "nope"}, ErrInvalidReason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Put(tc.rec); !errors.Is(err, tc.want) {
				t.Fatalf("Put = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPutGetDelete(t *testing.T) {
	s, _ := New("")
	if _, err := s.Put(Record{PathID: "ap-1", Owner: "alice", Reason: ReasonFalsePositive, Note: "scanner noise"}); err != nil {
		t.Fatal(err)
	}
	rec, ok := s.Get("default", "ap-1")
	if !ok {
		t.Fatal("expected ap-1 suppressed")
	}
	if rec.Owner != "alice" || rec.Reason != ReasonFalsePositive {
		t.Fatalf("unexpected record %+v", rec)
	}
	if rec.CreatedAt.IsZero() {
		t.Error("CreatedAt should be stamped")
	}
	if err := s.Delete("default", "ap-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("default", "ap-1"); ok {
		t.Fatal("expected ap-1 un-suppressed after delete")
	}
}

func TestExpiryReactivatesPath(t *testing.T) {
	s, _ := New("")
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	if _, err := s.Put(Record{PathID: "expired", Owner: "alice", Reason: ReasonAcceptRisk, ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(Record{PathID: "live", Owner: "alice", Reason: ReasonAcceptRisk, ExpiresAt: &future}); err != nil {
		t.Fatal(err)
	}

	if _, ok := s.Get("default", "expired"); ok {
		t.Error("expired suppression must read as absent (path active again)")
	}
	if _, ok := s.Get("default", "live"); !ok {
		t.Error("unexpired suppression must be in force")
	}

	active := s.ActiveSet("default")
	if _, ok := active["expired"]; ok {
		t.Error("ActiveSet must exclude expired")
	}
	if _, ok := active["live"]; !ok {
		t.Error("ActiveSet must include live")
	}

	// List shows both - lapsed decisions stay visible on the board.
	if got := len(s.List("default")); got != 2 {
		t.Errorf("List = %d, want 2 (incl. expired)", got)
	}
}

func TestTenantIsolation(t *testing.T) {
	s, _ := New("")
	_, _ = s.Put(Record{PathID: "ap-1", Tenant: "globex", Owner: "alice", Reason: ReasonAcceptRisk})
	if _, ok := s.Get("acme", "ap-1"); ok {
		t.Error("suppression must not leak across tenants")
	}
	if _, ok := s.Get("globex", "ap-1"); !ok {
		t.Error("suppression must be found under its own tenant")
	}
}

func TestPersistenceRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "suppressions.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	if _, err := s.Put(Record{PathID: "ap-9", Owner: "secops", Reason: ReasonMitigatingControl, ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}

	// Reopen from disk - the decision must survive a restart.
	s2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := s2.Get("default", "ap-9")
	if !ok {
		t.Fatal("expected ap-9 to survive reload")
	}
	if rec.Reason != ReasonMitigatingControl || rec.Owner != "secops" {
		t.Fatalf("reloaded record mismatch: %+v", rec)
	}
	if rec.ExpiresAt == nil || !rec.ExpiresAt.Equal(exp) {
		t.Fatalf("reloaded expiry mismatch: %v", rec.ExpiresAt)
	}
}

func TestNilStoreIsNoop(t *testing.T) {
	var s *Store
	if s.List("default") != nil {
		t.Error("nil store List should be nil")
	}
	if _, ok := s.Get("default", "ap-1"); ok {
		t.Error("nil store Get should be false")
	}
	if s.ActiveSet("default") != nil {
		t.Error("nil store ActiveSet should be nil")
	}
	if s.Persistent() {
		t.Error("nil store should not be persistent")
	}
}
