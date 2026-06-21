package history

import (
	"path/filepath"
	"testing"
	"time"
)

// clock lets a test drive s.now deterministically.
func newAt(t *testing.T, path string, start time.Time) (*Store, *time.Time) {
	t.Helper()
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	cur := start
	s.now = func() time.Time { return cur }
	s.sampleEvery = time.Minute
	return s, &cur
}

func obs(ids ...string) []Observation {
	out := make([]Observation, len(ids))
	for i, id := range ids {
		out[i] = Observation{ID: id, Route: "a → " + id, Score: 0.5}
	}
	return out
}

func TestPathAgeAndResolution(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s, cur := newAt(t, "", start)

	s.ObservePass("default", obs("p1", "p2"), 80)
	if rec, ok := s.Get("default", "p1"); !ok || !rec.Open || !rec.FirstSeen.Equal(start) {
		t.Fatalf("p1 should be open with first_seen=start, got %+v", rec)
	}

	// 3 days later p1 is gone (resolved); p2 still open.
	*cur = start.Add(72 * time.Hour)
	s.ObservePass("default", obs("p2"), 60)

	p1, _ := s.Get("default", "p1")
	if p1.Open || p1.ResolvedAt == nil {
		t.Fatalf("p1 should be resolved, got %+v", p1)
	}
	st := s.Stats("default")
	if st.OpenPaths != 1 || st.ResolvedPaths != 1 || st.MTTRCount != 1 {
		t.Fatalf("stats = %+v, want 1 open / 1 resolved / mttr count 1", st)
	}
	if got := time.Duration(st.MTTRSeconds) * time.Second; got != 72*time.Hour {
		t.Errorf("MTTR = %s, want 72h", got)
	}
	if st.OldestOpenSince == nil || !st.OldestOpenSince.Equal(start) {
		t.Errorf("oldest open since = %v, want %v", st.OldestOpenSince, start)
	}
}

func TestReopenIsARegression(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s, cur := newAt(t, "", start)

	s.ObservePass("default", obs("p1"), 50)
	*cur = start.Add(time.Hour)
	s.ObservePass("default", nil, 0) // p1 resolved
	*cur = start.Add(2 * time.Hour)
	s.ObservePass("default", obs("p1"), 50) // p1 back

	rec, _ := s.Get("default", "p1")
	if !rec.Open || rec.Reopens != 1 {
		t.Fatalf("p1 should be reopened once, got open=%v reopens=%d", rec.Open, rec.Reopens)
	}
	// first_seen resets to the new opening, so "open for" reflects this occurrence.
	if !rec.FirstSeen.Equal(start.Add(2 * time.Hour)) {
		t.Errorf("reopen should reset first_seen, got %v", rec.FirstSeen)
	}
}

func TestTrendCoalescesAndCaps(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s, cur := newAt(t, "", start)
	s.maxPoints = 3

	// Two samples within one sampleEvery window collapse to one point.
	s.ObservePass("default", obs("p1"), 10)
	*cur = start.Add(10 * time.Second)
	s.ObservePass("default", obs("p1"), 20)
	if got := len(s.Trend("default", 0)); got != 1 {
		t.Fatalf("within-window samples should coalesce to 1, got %d", got)
	}
	if pts := s.Trend("default", 0); pts[0].RiskPct != 20 {
		t.Errorf("coalesced point should hold the latest value, got %v", pts[0].RiskPct)
	}

	// Distinct windows accumulate, capped at maxPoints (ring).
	for i := 1; i <= 5; i++ {
		*cur = start.Add(time.Duration(i) * 2 * time.Minute)
		s.ObservePass("default", obs("p1"), float64(i))
	}
	if got := len(s.Trend("default", 0)); got != 3 {
		t.Fatalf("trend should be capped at maxPoints=3, got %d", got)
	}
}

// Regression: repeated within-window samples must NOT slide the window anchor
// forward (which would make it never append). After sampleEvery from the first
// sample, the next one appends.
func TestTrendWindowAnchorDoesNotSlide(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s, cur := newAt(t, "", start) // sampleEvery = 1m
	s.SampleTrend("default", 5, 50)
	for _, d := range []time.Duration{30 * time.Second, 50 * time.Second} {
		*cur = start.Add(d)
		s.SampleTrend("default", 5, 50)
	}
	if got := len(s.Trend("default", 0)); got != 1 {
		t.Fatalf("within-window samples should stay 1 point, got %d", got)
	}
	*cur = start.Add(61 * time.Second) // past the window anchored at start
	s.SampleTrend("default", 6, 60)
	if got := len(s.Trend("default", 0)); got != 2 {
		t.Fatalf("a sample past sampleEvery should append; got %d points", got)
	}
}

func TestPersistenceRoundtrip(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "nested", "history.json")
	s, _ := newAt(t, path, start)
	s.ObservePass("globex", obs("p9"), 42)

	s2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := s2.Get("globex", "p9")
	if !ok || !rec.Open || !rec.FirstSeen.Equal(start) {
		t.Fatalf("p9 should survive reload with its first_seen, got %+v ok=%v", rec, ok)
	}
	if got := len(s2.Trend("globex", 0)); got != 1 {
		t.Errorf("posture series should survive reload, got %d points", got)
	}
}

func TestNilStoreIsNoop(t *testing.T) {
	var s *Store
	s.ObservePass("default", obs("p1"), 1) // must not panic
	if _, ok := s.Get("default", "p1"); ok {
		t.Error("nil store Get should be false")
	}
	if s.Trend("default", 0) != nil || s.Persistent() {
		t.Error("nil store should be empty/non-persistent")
	}
	if st := s.Stats("default"); st.OpenPaths != 0 {
		t.Error("nil store Stats should be zero")
	}
}
