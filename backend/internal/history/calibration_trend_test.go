package history

import (
	"testing"
	"time"
)

// storeAt builds a store whose clock the test drives, so the sampling window can be
// crossed deliberately instead of by sleeping.
func storeAt(t *testing.T, now *time.Time) *Store {
	t.Helper()
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.now = func() time.Time { return *now }
	return s
}

// The calibration trend is what lets an operator watch a calibration programme
// accumulate evidence. Samples inside one window coalesce rather than accumulating, or
// a dashboard polling every five seconds would bury a month of real movement under
// thousands of identical points.
func TestSampleCalibrationCoalescesInsideTheWindow(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s := storeAt(t, &now)

	s.SampleCalibration("acme", 0.20, 0.30, 5)
	now = now.Add(time.Second) // same window
	s.SampleCalibration("acme", 0.15, 0.25, 9)

	got := s.CalibrationTrend("acme", 0)
	if len(got) != 1 {
		t.Fatalf("%d points after two samples in one window, want 1", len(got))
	}
	// The coalesced point must carry the LATEST numbers, not the first: the newest
	// measurement is the true one.
	if got[0].Brier != 0.15 || got[0].ECE != 0.25 || got[0].Samples != 9 {
		t.Errorf("coalesced point kept stale values: %+v", got[0])
	}
}

func TestSampleCalibrationAppendsAcrossWindows(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s := storeAt(t, &now)

	s.SampleCalibration("acme", 0.20, 0.30, 5)
	now = now.Add(24 * time.Hour) // well past any sampling window
	s.SampleCalibration("acme", 0.10, 0.12, 40)

	got := s.CalibrationTrend("acme", 0)
	if len(got) != 2 {
		t.Fatalf("%d points across two windows, want 2", len(got))
	}
	if !got[0].At.Before(got[1].At) {
		t.Error("points are not in chronological order, so a trend line would zig-zag")
	}
	if got[1].Brier != 0.10 {
		t.Errorf("latest point = %+v", got[1])
	}
}

// limit is what the dashboard uses to ask for the tail; it must return the MOST RECENT
// n, not the oldest, or the chart would show the beginning of the programme forever.
func TestCalibrationTrendLimitReturnsTheMostRecent(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s := storeAt(t, &now)
	for i := 0; i < 5; i++ {
		s.SampleCalibration("acme", float64(i)/100, 0.1, i)
		now = now.Add(24 * time.Hour)
	}

	got := s.CalibrationTrend("acme", 2)
	if len(got) != 2 {
		t.Fatalf("limit 2 returned %d points", len(got))
	}
	if got[1].Samples != 4 {
		t.Errorf("last point has samples=%d, want the newest (4)", got[1].Samples)
	}
}

// Tenants share the store; one tenant's calibration programme must not appear in
// another's trend.
func TestCalibrationTrendIsPerTenant(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s := storeAt(t, &now)
	s.SampleCalibration("acme", 0.2, 0.3, 5)
	if got := s.CalibrationTrend("other-corp", 0); len(got) != 0 {
		t.Fatalf("another tenant sees %d of acme's points", len(got))
	}
	if got := s.CalibrationTrend("acme", 0); len(got) != 1 {
		t.Fatalf("acme lost its own point: %d", len(got))
	}
}

// A nil store is the "history disabled" configuration, and every read has to stay safe
// rather than panicking the API that calls it on each poll.
func TestNilStoreIsSafe(t *testing.T) {
	var s *Store
	s.SampleCalibration("acme", 0.1, 0.1, 1) // must not panic
	if got := s.CalibrationTrend("acme", 0); got != nil {
		t.Errorf("nil store returned %v", got)
	}
	if s.Persistent() {
		t.Error("nil store reported itself persistent")
	}
}

func TestCalibrationTrendIsEmptyForAnUnknownTenant(t *testing.T) {
	now := time.Now()
	s := storeAt(t, &now)
	if got := s.CalibrationTrend("never-seen", 5); len(got) != 0 {
		t.Errorf("unknown tenant returned %d points", len(got))
	}
}

// The returned slice must be a copy: handing out the internal one lets a caller mutate
// the store's history by accident.
func TestCalibrationTrendReturnsACopy(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	s := storeAt(t, &now)
	s.SampleCalibration("acme", 0.2, 0.3, 5)

	got := s.CalibrationTrend("acme", 0)
	got[0].Brier = 99

	if again := s.CalibrationTrend("acme", 0); again[0].Brier == 99 {
		t.Error("mutating the returned slice changed the store's history")
	}
}
