package coverage

import (
	"testing"
	"time"
)

func storeAt(now *time.Time) *Store {
	s := New()
	s.now = func() time.Time { return *now }
	return s
}

func TestRecordAccumulatesPerSource(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	s := storeAt(&now)

	s.Record("acme", "trivy", 10, 4)
	now = now.Add(time.Minute)
	s.Record("acme", "trivy", 5, 2)
	s.Record("acme", "falco", 1, 0)

	got := s.Snapshot("acme")
	if len(got) != 2 {
		t.Fatalf("%d sources, want 2", len(got))
	}
	byName := map[string]Source{}
	for _, c := range got {
		byName[c.Source] = c
	}
	tr := byName["trivy"]
	if tr.Events != 2 || tr.Nodes != 15 || tr.Edges != 6 {
		t.Errorf("trivy accumulated %+v", tr)
	}
	if !tr.First.Before(tr.Last) {
		t.Errorf("first (%v) should precede last (%v)", tr.First, tr.Last)
	}
}

// The whole point: a source that has stopped reporting must say so. An engine answering
// from data that stopped arriving is the false-assurance case this package exists for.
func TestSilentSourceIsReportedStale(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	s := storeAt(&now)
	s.Record("acme", "trivy", 1, 1)

	now = now.Add(2 * time.Hour) // still inside the window
	if got := s.Snapshot("acme"); got[0].Stale {
		t.Errorf("a source heard from 2h ago is already stale")
	}

	now = now.Add(48 * time.Hour)
	got := s.Snapshot("acme")
	if !got[0].Stale {
		t.Fatalf("a source silent for 50h is not marked stale: %+v", got[0])
	}
	if got[0].Silent == "" {
		t.Error("stale source does not say how long it has been silent")
	}
}

// Staleness is evaluated on read, not written at record time: a source becomes stale by
// nothing happening, which no write can observe.
func TestStalenessIsEvaluatedOnRead(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	s := storeAt(&now).WithStaleAfter(time.Hour)
	s.Record("acme", "iam", 3, 3)

	now = now.Add(90 * time.Minute)
	if !s.Snapshot("acme")[0].Stale {
		t.Fatal("not stale after 90m with a 1h window")
	}
	// A fresh report clears it without any other call.
	s.Record("acme", "iam", 1, 0)
	if s.Snapshot("acme")[0].Stale {
		t.Fatal("still stale after reporting again")
	}
}

// Counts is what a caller uses to say "answering from data that stopped arriving":
// reported > 0 with fresh == 0 is the alarming shape.
func TestCountsSeparatesReportedFromFresh(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	s := storeAt(&now).WithStaleAfter(time.Hour)
	s.Record("acme", "trivy", 1, 1)
	s.Record("acme", "falco", 1, 1)

	if r, f := s.Counts("acme"); r != 2 || f != 2 {
		t.Fatalf("reported=%d fresh=%d, want 2/2", r, f)
	}
	now = now.Add(2 * time.Hour)
	if r, f := s.Counts("acme"); r != 2 || f != 0 {
		t.Fatalf("reported=%d fresh=%d after both went silent, want 2/0", r, f)
	}
}

// Tenants share the store; one tenant's coverage must never answer for another, or the
// isolation the product sells leaks into the very number meant to qualify it.
func TestCoverageIsPerTenant(t *testing.T) {
	now := time.Now()
	s := storeAt(&now)
	s.Record("acme", "trivy", 5, 5)
	if got := s.Snapshot("other-corp"); len(got) != 0 {
		t.Fatalf("another tenant sees %d of acme's sources", len(got))
	}
}

// An empty tenant string is the single-tenant deployment, and must land in the same
// bucket the ingest path uses for it.
func TestEmptyTenantIsTheDefaultTenant(t *testing.T) {
	now := time.Now()
	s := storeAt(&now)
	s.Record("", "trivy", 1, 1)
	if got := s.Snapshot("default"); len(got) != 1 {
		t.Fatalf("an empty tenant did not land in \"default\": %+v", got)
	}
}

// Never heard from: the honest answer is an empty set, not an error and not a zeroed
// row that would read as "reported nothing" rather than "never reported".
func TestUnknownTenantHasNoCoverage(t *testing.T) {
	now := time.Now()
	if got := storeAt(&now).Snapshot("never-seen"); len(got) != 0 {
		t.Fatalf("got %d sources for a tenant that never ingested", len(got))
	}
}

// A nil store is the "coverage disabled" wiring, and every method has to stay safe -
// this is called on the ingest hot path.
func TestNilStoreIsSafe(t *testing.T) {
	var s *Store
	s.Record("acme", "trivy", 1, 1)
	if got := s.Snapshot("acme"); got != nil {
		t.Errorf("nil store returned %v", got)
	}
	if r, f := s.Counts("acme"); r != 0 || f != 0 {
		t.Errorf("nil store counted %d/%d", r, f)
	}
}

// An unnamed source would produce a row nobody can act on, so it is dropped rather than
// recorded as "".
func TestUnnamedSourceIsIgnored(t *testing.T) {
	now := time.Now()
	s := storeAt(&now)
	s.Record("acme", "", 1, 1)
	if got := s.Snapshot("acme"); len(got) != 0 {
		t.Fatalf("recorded an unnamed source: %+v", got)
	}
}

func TestSnapshotIsOrderedMostRecentFirst(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	s := storeAt(&now)
	s.Record("acme", "old", 1, 1)
	now = now.Add(time.Hour)
	s.Record("acme", "new", 1, 1)

	got := s.Snapshot("acme")
	if got[0].Source != "new" {
		t.Fatalf("order is %s,%s - want most recent first", got[0].Source, got[1].Source)
	}
}

// Snapshot must copy: handing out the internal pointers lets a reader mutate the
// engine's own record of what it has seen.
func TestSnapshotReturnsCopies(t *testing.T) {
	now := time.Now()
	s := storeAt(&now)
	s.Record("acme", "trivy", 10, 10)

	got := s.Snapshot("acme")
	got[0].Nodes = 99999

	if again := s.Snapshot("acme"); again[0].Nodes != 10 {
		t.Errorf("mutating the snapshot changed the store: %d", again[0].Nodes)
	}
}
