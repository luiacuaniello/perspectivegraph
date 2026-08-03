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
	"sort"
	"sync"
	"time"
)

type event struct {
	at time.Time
	n  int
}

// DefaultMaxKeys bounds how many distinct keys one Watcher tracks.
//
// This is a security control, and without a bound it is also an attack on the process
// that runs it. The brute-force watcher is keyed by REMOTE IP and fed from the
// pre-authentication path - failed logins - so anyone who can reach the endpoint chooses
// the keys, and a single IPv6 /64 offers 2^64 of them. Expiring the events inside a key
// is not enough: the key, its slice header and its entry in lastAlert survive every
// event that justified them.
//
// So the bound is two-part, and both parts are needed. Time-based sweeping alone leaves
// the whole inter-sweep interval unbounded, which is a flood window, not a bound; a hard
// cap alone would let long-dead keys hold the budget against live ones.
const DefaultMaxKeys = 50_000

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
	maxKeys   int
	lastSweep time.Time
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
		maxKeys:   DefaultMaxKeys,
		lastSweep: time.Now(),
	}
}

// WithMaxKeys overrides the tracked-key ceiling. Returns the watcher for chaining.
func (w *Watcher) WithMaxKeys(n int) *Watcher {
	if n > 0 {
		w.maxKeys = n
	}
	return w
}

// TrackedKeys reports how many keys are currently held. Exported so a test can assert
// the bound actually holds, and so an operator can see the watcher's footprint.
func (w *Watcher) TrackedKeys() int {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.events)
}

// sweepLocked drops keys whose events have all aged out of the window, and alert
// timestamps past their cooldown. A key is only revisited when it is observed again, so
// without this pass a key seen once is held forever.
func (w *Watcher) sweepLocked(now time.Time) {
	cutoff := now.Add(-w.window)
	for k, evs := range w.events {
		live := false
		for _, e := range evs {
			if e.at.After(cutoff) {
				live = true
				break
			}
		}
		if !live {
			delete(w.events, k)
		}
	}
	for k, t := range w.lastAlert {
		if now.Sub(t) >= w.cooldown {
			delete(w.lastAlert, k)
		}
	}
	w.lastSweep = now
}

// evictOldestLocked forces the map back under `target` by dropping the least recently
// active keys. It runs only when the cap is already breached, and overshoots downward so
// a flood does not re-trigger it on every subsequent call.
//
// Evicting the OLDEST rather than refusing new keys is deliberate: under a flood the
// newest keys are the ones an attacker just minted, but so is any genuine brute-forcer
// arriving now. Refusing new keys would let a flood blind the very detector it floods.
func (w *Watcher) evictOldestLocked(target int) {
	type ka struct {
		key  string
		last time.Time
	}
	all := make([]ka, 0, len(w.events))
	for k, evs := range w.events {
		var last time.Time
		if n := len(evs); n > 0 {
			last = evs[n-1].at
		}
		all = append(all, ka{k, last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last.Before(all[j].last) })
	for i := 0; i < len(all)-target && i < len(all); i++ {
		delete(w.events, all[i].key)
		delete(w.lastAlert, all[i].key)
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

	// Bound the key space. The timed sweep reclaims keys nobody will ever observe
	// again; the cap is what holds during a burst that outruns it.
	if now.Sub(w.lastSweep) >= w.window {
		w.sweepLocked(now)
	}
	if len(w.events) > w.maxKeys {
		w.sweepLocked(now)
		if len(w.events) > w.maxKeys {
			w.evictOldestLocked(w.maxKeys * 3 / 4)
		}
	}

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
