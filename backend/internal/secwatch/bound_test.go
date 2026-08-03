package secwatch

import (
	"fmt"
	"testing"
	"time"
)

// The brute-force watcher is keyed by remote IP and fed from the PRE-authentication
// path, so the key space belongs to whoever can reach the port. Before this bound, every
// distinct IP left two permanent map entries behind - expiring a key's events never
// removed the key - so an IPv6 rotation turned the abuse detector into the abuse.
func TestKeySpaceIsBoundedUnderFlood(t *testing.T) {
	now := time.Now()
	w := New(5, time.Minute, time.Minute, nil).WithMaxKeys(1000)
	w.now = func() time.Time { return now }

	for i := 0; i < 200_000; i++ {
		w.Observe(fmt.Sprintf("2001:db8::%x", i), 1)
	}

	if got := w.TrackedKeys(); got > 1000 {
		t.Fatalf("tracking %d keys after a 200k-address flood, cap is 1000", got)
	}
	w.mu.Lock()
	alerts := len(w.lastAlert)
	w.mu.Unlock()
	if alerts > 1000 {
		t.Errorf("lastAlert holds %d entries - it is bounded separately and was not", alerts)
	}
}

// Bounding must not blind the detector: a real brute-forcer arriving during a flood is
// exactly the case the watcher exists for, and eviction drops the OLDEST keys so the
// newcomer keeps its counter.
func TestDetectionStillWorksAfterFlood(t *testing.T) {
	now := time.Now()
	var fired []string
	w := New(3, time.Minute, time.Minute, func(k string, n int) { fired = append(fired, k) }).
		WithMaxKeys(100)
	w.now = func() time.Time { return now }

	for i := 0; i < 5000; i++ {
		w.Observe(fmt.Sprintf("flood-%d", i), 1)
	}
	for i := 0; i < 3; i++ {
		w.Observe("10.0.0.9", 1)
	}

	if len(fired) == 0 || fired[len(fired)-1] != "10.0.0.9" {
		t.Fatalf("brute-forcer not detected after a flood; alerts=%v", fired)
	}
	if !w.Tripped("10.0.0.9") {
		t.Error("the tripped key is not locked out")
	}
}

// Keys whose events have all aged out are reclaimed even when they are never observed
// again - the sweep exists because nothing else ever revisits them.
func TestSilentKeysAreReclaimed(t *testing.T) {
	now := time.Now()
	w := New(100, time.Minute, time.Minute, nil)
	w.now = func() time.Time { return now }

	for i := 0; i < 500; i++ {
		w.Observe(fmt.Sprintf("ip-%d", i), 1)
	}
	if got := w.TrackedKeys(); got != 500 {
		t.Fatalf("holding %d keys, want 500 before any expiry", got)
	}

	now = now.Add(2 * time.Minute) // everything above is now outside the window
	w.Observe("someone-new", 1)    // the sweep runs on the next observation

	if got := w.TrackedKeys(); got != 1 {
		t.Fatalf("holding %d keys after every earlier event expired, want 1", got)
	}
}

// A key still inside its window must survive the sweep, or the detector would forget
// an attack in progress.
func TestLiveKeysSurviveTheSweep(t *testing.T) {
	now := time.Now()
	w := New(10, time.Minute, time.Minute, nil)
	w.now = func() time.Time { return now }

	w.Observe("attacker", 1)
	now = now.Add(90 * time.Second) // past the sweep interval
	w.Observe("attacker", 1)        // ...but this refreshes it

	now = now.Add(30 * time.Second)
	w.Observe("other", 1)

	if !hasKey(w, "attacker") {
		t.Fatal("an attacker seen 30s ago was swept away")
	}
}

func hasKey(w *Watcher, k string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.events[k]
	return ok
}
