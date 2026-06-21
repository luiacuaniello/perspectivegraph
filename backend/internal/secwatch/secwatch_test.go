package secwatch

import (
	"testing"
	"time"
)

func TestDisabledIsNoop(t *testing.T) {
	w := New(0, time.Minute, time.Minute, func(string, int) { t.Fatal("must not alert") })
	if w.Enabled() {
		t.Fatal("threshold 0 must be disabled")
	}
	if w.Observe("k", 100) || w.Tripped("k") {
		t.Fatal("disabled watcher must be a no-op")
	}
}

func TestThresholdAndCooldown(t *testing.T) {
	now := time.Unix(0, 0)
	alerts := 0
	w := New(5, time.Minute, 10*time.Minute, func(string, int) { alerts++ })
	w.now = func() time.Time { return now }

	// 4 events: below threshold, no alert, not tripped.
	for i := 0; i < 4; i++ {
		if w.Observe("ip", 1) {
			t.Fatalf("alert fired early at %d", i)
		}
	}
	if w.Tripped("ip") || alerts != 0 {
		t.Fatal("should not be tripped below threshold")
	}

	// 5th crosses the threshold → one alert, now tripped (locked).
	if !w.Observe("ip", 1) {
		t.Fatal("5th event should trip the threshold")
	}
	if alerts != 1 || !w.Tripped("ip") {
		t.Fatalf("alerts=%d tripped=%v, want 1/true", alerts, w.Tripped("ip"))
	}

	// More events during cooldown don't re-alert.
	now = now.Add(time.Minute)
	w.Observe("ip", 10)
	if alerts != 1 {
		t.Fatalf("alerts=%d during cooldown, want 1", alerts)
	}

	// After cooldown the lock lifts.
	now = now.Add(11 * time.Minute)
	if w.Tripped("ip") {
		t.Fatal("lock should lift after cooldown")
	}
}

func TestWindowExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	w := New(3, time.Minute, time.Minute, func(string, int) {})
	w.now = func() time.Time { return now }

	w.Observe("k", 1)
	w.Observe("k", 1)
	now = now.Add(2 * time.Minute) // first two events age out of the window
	if w.Observe("k", 1) {
		t.Fatal("stale events should have expired; threshold not reached")
	}
}

func TestWeightedCount(t *testing.T) {
	// A single bulk export (n=large) trips on its own — the exfil case.
	w := New(100, time.Minute, time.Minute, func(string, int) {})
	if !w.Observe("principal", 250) {
		t.Fatal("a single large-count observation should trip the threshold")
	}
}
