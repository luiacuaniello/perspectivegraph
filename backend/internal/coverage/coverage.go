// Package coverage records what the engine has actually been fed, so "no attack path
// found" can be told apart from "nothing was ever ingested about that part of the
// estate".
//
// This is the honesty gap the rest of the product does not cover. Every other number
// here is careful about what it shows: a hop declares whether it is evidence or an
// estimate, the calibration report says when it has too few samples to judge, the
// positioning says which clouds are live. But a path-finding engine fed by incomplete
// scanners produces FALSE NEGATIVES, and a false negative is invisible - nobody opens a
// ticket for a route they were never shown. A green board over a region no collector
// ever reached is not good news; it is no news wearing good news' clothes.
//
// So coverage is deliberately about ABSENCE. It answers "which sources have reported,
// how recently, and how much", which lets a caller state the one thing the engine
// cannot otherwise say: this verdict covers what I was shown, and here is what I was
// not shown.
//
// Scope, stated because it bounds the claim: this records what reached THIS process's
// ingest endpoint. It is not an inventory of the estate and cannot be - the engine has
// no way to know an account exists if nothing ever mentions it. It turns "silence"
// into "silence from source X since T", which is the actionable half.
package coverage

import (
	"sort"
	"sync"
	"time"
)

// Source is what one collector has contributed to one tenant's graph.
type Source struct {
	Source string    `json:"source"`               // collector name: trivy, falco, iam, …
	First  time.Time `json:"first_seen"`           // when this source was first heard from
	Last   time.Time `json:"last_seen"`            // and most recently
	Events int       `json:"events"`               // ingest calls accepted
	Nodes  int       `json:"nodes"`                // assets contributed
	Edges  int       `json:"edges"`                // relationships contributed
	Stale  bool      `json:"stale,omitempty"`      // silent for longer than the staleness window
	Silent string    `json:"silent_for,omitempty"` // human duration since Last, when stale
}

// DefaultStaleAfter is when a source stops counting as current. A scanner that ran a
// day ago is describing yesterday's estate, and a path-finding result built on it
// should say so rather than present itself as today's answer.
const DefaultStaleAfter = 24 * time.Hour

// Store accumulates per-tenant, per-source ingest facts. It is in-memory on purpose:
// the question it answers is "what has this engine been told recently", which a restart
// legitimately resets - a fresh process genuinely has not been told anything yet, and
// claiming otherwise from a file would be the exact false assurance this package exists
// to prevent.
type Store struct {
	mu         sync.RWMutex
	byTenant   map[string]map[string]*Source
	staleAfter time.Duration
	now        func() time.Time
}

func New() *Store {
	return &Store{
		byTenant:   map[string]map[string]*Source{},
		staleAfter: DefaultStaleAfter,
		now:        time.Now,
	}
}

// WithStaleAfter overrides the staleness window. Returns the store for chaining.
func (s *Store) WithStaleAfter(d time.Duration) *Store {
	if d > 0 {
		s.staleAfter = d
	}
	return s
}

// Record notes one accepted ingest. A nil store is a no-op so callers need no guard.
func (s *Store) Record(tenant, source string, nodes, edges int) {
	if s == nil || source == "" {
		return
	}
	if tenant == "" {
		tenant = "default"
	}
	now := s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()
	byS := s.byTenant[tenant]
	if byS == nil {
		byS = map[string]*Source{}
		s.byTenant[tenant] = byS
	}
	c := byS[source]
	if c == nil {
		c = &Source{Source: source, First: now}
		byS[source] = c
	}
	c.Last = now
	c.Events++
	c.Nodes += nodes
	c.Edges += edges
}

// Snapshot returns the tenant's sources, most recently heard from first, with staleness
// evaluated at read time rather than stored - a source does not become stale by an event
// happening, it becomes stale by nothing happening.
func (s *Store) Snapshot(tenant string) []Source {
	if s == nil {
		return nil
	}
	if tenant == "" {
		tenant = "default"
	}
	now := s.now().UTC()

	s.mu.RLock()
	defer s.mu.RUnlock()
	byS := s.byTenant[tenant]
	out := make([]Source, 0, len(byS))
	for _, c := range byS {
		v := *c
		if silence := now.Sub(v.Last); silence > s.staleAfter {
			v.Stale = true
			v.Silent = humanDuration(silence)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Last.Equal(out[j].Last) {
			return out[i].Last.After(out[j].Last)
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// Reported is how many sources have ever been heard from, and Fresh how many are still
// current. Fresh == 0 with Reported > 0 is the case worth shouting about: the engine is
// answering from data that has stopped arriving.
func (s *Store) Counts(tenant string) (reported, fresh int) {
	for _, c := range s.Snapshot(tenant) {
		reported++
		if !c.Stale {
			fresh++
		}
	}
	return reported, fresh
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return itoa(int(d.Hours()/24)) + "d"
	case d >= 2*time.Hour:
		return itoa(int(d.Hours())) + "h"
	case d >= 2*time.Minute:
		return itoa(int(d.Minutes())) + "m"
	default:
		return itoa(int(d.Seconds())) + "s"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
