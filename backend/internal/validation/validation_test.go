package validation

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestPutValidation(t *testing.T) {
	s, _ := New("")
	cases := []struct {
		name string
		rec  Record
		want error
	}{
		{"bad outcome", Record{Outcome: "nope", Source: "caldera", PathID: "ap-1"}, ErrInvalidOutcome},
		{"missing source", Record{Outcome: Confirmed, PathID: "ap-1"}, ErrMissingSource},
		{"missing path (non-missed)", Record{Outcome: Confirmed, Source: "caldera"}, ErrMissingPathID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.Put(tc.rec); !errors.Is(err, tc.want) {
				t.Fatalf("Put = %v, want %v", err, tc.want)
			}
		})
	}
	// "missed" is allowed without a PathID.
	if _, err := s.Put(Record{Outcome: Missed, Source: "redteam", Route: "internet → saas → db"}); err != nil {
		t.Fatalf("missed verdict should be allowed without path id: %v", err)
	}
}

func TestLatestVerdictPerPathWins(t *testing.T) {
	s, _ := New("")
	_, _ = s.Put(Record{Outcome: Refuted, Source: "bas", PathID: "ap-1"})
	_, _ = s.Put(Record{Outcome: Confirmed, Source: "redteam", PathID: "ap-1"}) // retest
	rec, ok := s.Get("default", "ap-1")
	if !ok || rec.Outcome != Confirmed || rec.Source != "redteam" {
		t.Fatalf("latest verdict should win, got %+v ok=%v", rec, ok)
	}
	if m := s.Metrics("default"); m.Confirmed != 1 || m.Refuted != 0 {
		t.Errorf("retest should not double-count: %+v", m)
	}
}

func TestPrecisionRecall(t *testing.T) {
	s, _ := New("")
	// 3 confirmed, 1 refuted ⇒ precision 0.75; 1 missed ⇒ recall 3/4 = 0.75.
	for _, id := range []string{"ap-1", "ap-2", "ap-3"} {
		_, _ = s.Put(Record{Outcome: Confirmed, Source: "caldera", PathID: id})
	}
	_, _ = s.Put(Record{Outcome: Refuted, Source: "caldera", PathID: "ap-4"})
	_, _ = s.Put(Record{Outcome: Partial, Source: "caldera", PathID: "ap-5"})
	_, _ = s.Put(Record{Outcome: Missed, Source: "redteam", Route: "okta → admin"})

	m := s.Metrics("default")
	if m.Confirmed != 3 || m.Refuted != 1 || m.Partial != 1 || m.Missed != 1 {
		t.Fatalf("counts wrong: %+v", m)
	}
	if m.Tested != 5 {
		t.Errorf("tested = %d, want 5", m.Tested)
	}
	if m.Precision < 0.749 || m.Precision > 0.751 {
		t.Errorf("precision = %v, want 0.75", m.Precision)
	}
	if m.Recall < 0.749 || m.Recall > 0.751 {
		t.Errorf("recall = %v, want 0.75", m.Recall)
	}
	if !m.HasData {
		t.Error("HasData should be true with verdicts present")
	}
}

func TestEmptyMetricsUndefined(t *testing.T) {
	s, _ := New("")
	if m := s.Metrics("default"); m.HasData {
		t.Error("no verdicts ⇒ precision/recall undefined (HasData false)")
	}
}

func TestPersistenceRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "validations.json")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Put(Record{Outcome: Confirmed, Source: "redteam", PathID: "ap-9", Tenant: "globex", Evidence: "caldera run #42"})

	s2, _ := New(path)
	rec, ok := s2.Get("globex", "ap-9")
	if !ok || rec.Outcome != Confirmed || rec.Evidence != "caldera run #42" {
		t.Fatalf("verdict should survive reload: %+v ok=%v", rec, ok)
	}
}

func TestNilStoreIsNoop(t *testing.T) {
	var s *Store
	if s.List("default") != nil || s.Persistent() {
		t.Error("nil store should be empty/non-persistent")
	}
	if _, ok := s.Get("default", "ap-1"); ok {
		t.Error("nil store Get should be false")
	}
	if m := s.Metrics("default"); m.HasData {
		t.Error("nil store Metrics should be empty")
	}
}
