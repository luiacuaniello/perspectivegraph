// Package secwatch is a small sliding-window threshold detector shared by the
// two abuse signals the tool watches about ITSELF: bulk read/export of the
// attack map (exfiltration) and repeated authentication failures (brute force).
//
// A Watcher counts weighted events per key within a window and fires a single
// alert when the count crosses a threshold, then stays quiet for a cooldown so a
// sustained attack doesn't storm the alert channel. Tripped reports whether a key
// is currently in its post-trip cooldown - used to lock out a brute-forcing IP.
// A nil or zero-threshold Watcher is a no-op, so callers never branch.
package secwatch

import (
	"sync"
	"time"
)

type event struct {
	at time.Time
	n  int
}

// Watcher is safe for concurrent use.
type Watcher struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	cooldown  time.Duration
	now       func() time.Time
	events    map[string][]event
	lastAlert map[string]time.Time
	onAlert   func(key string, count int)
}

// New builds a Watcher. threshold <= 0 disables it (every method is a no-op).
// onAlert is invoked (synchronously) the first time a key crosses threshold and
// again only after cooldown elapses.
func New(threshold int, window, cooldown time.Duration, onAlert func(key string, count int)) *Watcher {
	return &Watcher{
		threshold: threshold,
		window:    window,
		cooldown:  cooldown,
		now:       time.Now,
		events:    map[string][]event{},
		lastAlert: map[string]time.Time{},
		onAlert:   onAlert,
	}
}

// Enabled reports whether the watcher is active.
func (w *Watcher) Enabled() bool { return w != nil && w.threshold > 0 }

// Observe adds n (min 1) to key's windowed count and returns true if this call
// crossed the threshold and fired an alert.
func (w *Watcher) Observe(key string, n int) bool {
	if !w.Enabled() {
		return false
	}
	if n <= 0 {
		n = 1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	cutoff := now.Add(-w.window)

	kept := w.events[key][:0]
	sum := 0
	for _, e := range w.events[key] {
		if e.at.After(cutoff) {
			kept = append(kept, e)
			sum += e.n
		}
	}
	kept = append(kept, event{at: now, n: n})
	sum += n
	w.events[key] = kept

	if sum < w.threshold {
		return false
	}
	if last, ok := w.lastAlert[key]; ok && now.Sub(last) < w.cooldown {
		return false // already alerted recently - stay quiet
	}
	w.lastAlert[key] = now
	if w.onAlert != nil {
		w.onAlert(key, sum)
	}
	return true
}

// Tripped reports whether key is within the cooldown following a trip - i.e.
// currently "locked". Used to short-circuit a brute-forcing client.
func (w *Watcher) Tripped(key string) bool {
	if !w.Enabled() {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	last, ok := w.lastAlert[key]
	return ok && w.now().Sub(last) < w.cooldown
}
