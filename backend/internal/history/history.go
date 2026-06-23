// Package history gives PerspectiveGraph a memory: it turns the analyzer's
// point-in-time passes into a time series, so the questions security management
// actually asks have answers - "how long has this path been open?", "what's our
// MTTR?", "is our exposure trending down?", "did that path we fixed come back?".
//
// It records two things per tenant, fed once per (changed) analyzer pass:
//
//   - Per-path lifecycle: first/last seen, open/resolved, and reopen count.
//     first_seen survives restarts (it is persisted), so "open for 5 days" is real.
//   - A posture series: a downsampled (active-paths, risk%) sample over time, the
//     trend a management dashboard plots.
//
// MTTR falls out of the lifecycle: when a path stops appearing it is marked
// resolved, and resolved−first_seen is its time-to-remediate.
package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// defaults bound the on-disk/in-memory footprint and the trend resolution.
const (
	// defaultSampleEvery coalesces posture samples: at most one point per window,
	// so a fast analyzer interval doesn't flood the series with near-duplicates.
	defaultSampleEvery = time.Minute
	// defaultMaxPoints caps the per-tenant posture ring buffer.
	defaultMaxPoints = 2000
)

// Observation is one open attack path seen on a pass.
type Observation struct {
	ID    string
	Route string
	Score float64
}

// PathRecord is the lifecycle of one attack path (keyed by its stable id).
type PathRecord struct {
	ID         string     `json:"id"`
	Tenant     string     `json:"tenant"`
	Route      string     `json:"route"`
	Score      float64    `json:"score"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	Open       bool       `json:"open"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	Reopens    int        `json:"reopens"`
}

// PosturePoint is one sample of the exposure trend.
type PosturePoint struct {
	At            time.Time `json:"at"`
	CriticalPaths int       `json:"critical_paths"`
	RiskPct       float64   `json:"risk_pct"` // P(any crown jewel compromised) × 100
}

// CalibrationSample is one point of the calibration trend - the headline calibration
// numbers over time, so an operator can watch the evidence accumulate (and see when a
// calibration program is actually improving the scores).
type CalibrationSample struct {
	At      time.Time `json:"at"`
	Brier   float64   `json:"brier"`
	ECE     float64   `json:"ece"`
	Samples int       `json:"samples"`
}

// Stats is the rolled-up temporal summary for a tenant.
type Stats struct {
	OpenPaths       int
	ResolvedPaths   int
	MTTRSeconds     float64    // mean (resolved−first_seen) over resolved occurrences
	MTTRCount       int        // how many resolutions the MTTR averages over
	OldestOpenSince *time.Time // first_seen of the longest-open path
}

type tenantHistory struct {
	paths       map[string]*PathRecord
	posture     []PosturePoint
	calibration []CalibrationSample
}

// Store is an in-memory, optionally file-backed temporal store, isolated per
// tenant and safe for concurrent use. A nil *Store is a valid no-op.
type Store struct {
	mu          sync.RWMutex
	path        string
	byTenant    map[string]*tenantHistory
	now         func() time.Time
	sampleEvery time.Duration
	maxPoints   int
	sealer      cryptostore.Sealer
}

// Option configures a Store.
type Option func(*Store)

// WithSealer encrypts the on-disk file at rest (and decrypts on load). The
// default Nop sealer writes plaintext.
func WithSealer(sealer cryptostore.Sealer) Option {
	return func(s *Store) {
		if sealer != nil {
			s.sealer = sealer
		}
	}
}

// New builds a store, loading prior history from disk when path is set.
func New(path string, opts ...Option) (*Store, error) {
	s := &Store{
		path:        path,
		byTenant:    map[string]*tenantHistory{},
		now:         time.Now,
		sampleEvery: defaultSampleEvery,
		maxPoints:   defaultMaxPoints,
		sealer:      cryptostore.Nop(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if path == "" {
		return s, nil
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Persistent reports whether history is file-backed (survives restarts).
func (s *Store) Persistent() bool { return s != nil && s.path != "" }

func (s *Store) tenant(t string) *tenantHistory {
	th := s.byTenant[t]
	if th == nil {
		th = &tenantHistory{paths: map[string]*PathRecord{}}
		s.byTenant[t] = th
	}
	return th
}

// ObservePass folds one analyzer pass into the history: it ages the still-open
// paths, opens new ones, reopens ones that came back, resolves ones that vanished
// (feeding MTTR), and appends a downsampled posture sample. It then persists.
func (s *Store) ObservePass(tenant string, open []Observation, riskPct float64) {
	if s == nil {
		return
	}
	now := s.now().UTC()

	s.mu.Lock()
	th := s.tenant(tenant)
	seen := make(map[string]bool, len(open))
	for _, o := range open {
		seen[o.ID] = true
		rec := th.paths[o.ID]
		switch {
		case rec == nil:
			th.paths[o.ID] = &PathRecord{
				ID: o.ID, Tenant: tenant, Route: o.Route, Score: o.Score,
				FirstSeen: now, LastSeen: now, Open: true,
			}
		case !rec.Open:
			// Resolved before and back now: a regression. Start a fresh opening
			// (first_seen resets so "open for" reflects this occurrence) and count it.
			rec.Open = true
			rec.ResolvedAt = nil
			rec.FirstSeen = now
			rec.LastSeen = now
			rec.Route = o.Route
			rec.Score = o.Score
			rec.Reopens++
		default:
			rec.LastSeen = now
			rec.Route = o.Route
			rec.Score = o.Score
		}
	}
	// Anything open last pass but gone now is resolved → contributes to MTTR.
	for id, rec := range th.paths {
		if rec.Open && !seen[id] {
			rec.Open = false
			t := now
			rec.ResolvedAt = &t
		}
	}
	s.appendPosture(th, PosturePoint{At: now, CriticalPaths: len(open), RiskPct: riskPct})
	s.mu.Unlock()

	// Lifecycle changed, so always flush.
	_ = s.persist() // history is best-effort observability; never fail a pass over it
}

// SampleTrend records a posture point only (no path lifecycle), so the exposure
// trend stays continuous on analyzer passes that change-detection skipped - a
// steady "12 paths for the last hour" line is itself information. Coalesced to one
// point per window; it only flushes to disk when it actually appends a new point.
func (s *Store) SampleTrend(tenant string, criticalPaths int, riskPct float64) {
	if s == nil {
		return
	}
	now := s.now().UTC()
	s.mu.Lock()
	th := s.tenant(tenant)
	appended := s.appendPosture(th, PosturePoint{At: now, CriticalPaths: criticalPaths, RiskPct: riskPct})
	s.mu.Unlock()
	if appended {
		_ = s.persist()
	}
}

// appendPosture adds a sample, coalescing to one per sampleEvery window (an
// in-window sample updates the last point instead of appending). Caller holds the
// lock. Returns true when a new point was appended (vs. coalesced).
func (s *Store) appendPosture(th *tenantHistory, pt PosturePoint) bool {
	if n := len(th.posture); n > 0 && pt.At.Sub(th.posture[n-1].At) < s.sampleEvery {
		// Coalesce: refresh the value but keep At anchored to the window's start,
		// so the window doesn't slide forward forever and never append.
		th.posture[n-1].CriticalPaths = pt.CriticalPaths
		th.posture[n-1].RiskPct = pt.RiskPct
		return false
	}
	th.posture = append(th.posture, pt)
	if len(th.posture) > s.maxPoints {
		th.posture = th.posture[len(th.posture)-s.maxPoints:]
	}
	return true
}

// SampleCalibration records a point of the calibration trend (Brier/ECE/sample-count),
// coalesced to one per window like the posture trend, so an operator can watch the
// evidence accumulate over a calibration program without flooding the series.
func (s *Store) SampleCalibration(tenant string, brier, ece float64, samples int) {
	if s == nil {
		return
	}
	now := s.now().UTC()
	s.mu.Lock()
	th := s.tenant(tenant)
	pt := CalibrationSample{At: now, Brier: brier, ECE: ece, Samples: samples}
	appended := false
	if n := len(th.calibration); n > 0 && pt.At.Sub(th.calibration[n-1].At) < s.sampleEvery {
		th.calibration[n-1].Brier = pt.Brier // coalesce within the window
		th.calibration[n-1].ECE = pt.ECE
		th.calibration[n-1].Samples = pt.Samples
	} else {
		th.calibration = append(th.calibration, pt)
		if len(th.calibration) > s.maxPoints {
			th.calibration = th.calibration[len(th.calibration)-s.maxPoints:]
		}
		appended = true
	}
	s.mu.Unlock()
	if appended {
		_ = s.persist()
	}
}

// Get returns the lifecycle record for a path, if tracked.
func (s *Store) Get(tenant, id string) (PathRecord, bool) {
	if s == nil {
		return PathRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if th := s.byTenant[tenant]; th != nil {
		if rec, ok := th.paths[id]; ok {
			return *rec, true
		}
	}
	return PathRecord{}, false
}

// Trend returns the most recent posture samples (oldest first), capped to limit
// (0 = all retained).
func (s *Store) Trend(tenant string, limit int) []PosturePoint {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	th := s.byTenant[tenant]
	if th == nil {
		return nil
	}
	pts := th.posture
	if limit > 0 && limit < len(pts) {
		pts = pts[len(pts)-limit:]
	}
	out := make([]PosturePoint, len(pts))
	copy(out, pts)
	return out
}

// CalibrationTrend returns the most recent calibration samples (oldest first), capped
// to limit (0 = all retained).
func (s *Store) CalibrationTrend(tenant string, limit int) []CalibrationSample {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	th := s.byTenant[tenant]
	if th == nil {
		return nil
	}
	pts := th.calibration
	if limit > 0 && limit < len(pts) {
		pts = pts[len(pts)-limit:]
	}
	out := make([]CalibrationSample, len(pts))
	copy(out, pts)
	return out
}

// Stats rolls up the tenant's temporal summary (open count, MTTR, oldest-open).
func (s *Store) Stats(tenant string) Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	th := s.byTenant[tenant]
	if th == nil {
		return Stats{}
	}
	var st Stats
	var total float64
	for _, rec := range th.paths {
		if rec.Open {
			st.OpenPaths++
			if st.OldestOpenSince == nil || rec.FirstSeen.Before(*st.OldestOpenSince) {
				fs := rec.FirstSeen
				st.OldestOpenSince = &fs
			}
			continue
		}
		if rec.ResolvedAt != nil {
			st.ResolvedPaths++
			total += rec.ResolvedAt.Sub(rec.FirstSeen).Seconds()
			st.MTTRCount++
		}
	}
	if st.MTTRCount > 0 {
		st.MTTRSeconds = total / float64(st.MTTRCount)
	}
	return st
}

// ── persistence ─────────────────────────────────────────────────────

type postureRow struct {
	Tenant string `json:"tenant"`
	PosturePoint
}

type calibrationRow struct {
	Tenant string `json:"tenant"`
	CalibrationSample
}

type fileShape struct {
	Paths       []PathRecord     `json:"paths"`
	Posture     []postureRow     `json:"posture"`
	Calibration []calibrationRow `json:"calibration,omitempty"`
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(b) == 0) {
		return nil
	}
	if err != nil {
		return err
	}
	if b, err = s.sealer.Open(b); err != nil {
		return fmt.Errorf("history: decrypt %s: %w", s.path, err)
	}
	var f fileShape
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("history: parse %s: %w", s.path, err)
	}
	for i := range f.Paths {
		rec := f.Paths[i]
		th := s.tenant(rec.Tenant)
		r := rec
		th.paths[rec.ID] = &r
	}
	for _, row := range f.Posture {
		th := s.tenant(row.Tenant)
		th.posture = append(th.posture, row.PosturePoint)
	}
	for _, row := range f.Calibration {
		th := s.tenant(row.Tenant)
		th.calibration = append(th.calibration, row.CalibrationSample)
	}
	return nil
}

func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	var f fileShape
	for tenant, th := range s.byTenant {
		for _, rec := range th.paths {
			f.Paths = append(f.Paths, *rec)
		}
		for _, pt := range th.posture {
			f.Posture = append(f.Posture, postureRow{Tenant: tenant, PosturePoint: pt})
		}
		for _, pt := range th.calibration {
			f.Calibration = append(f.Calibration, calibrationRow{Tenant: tenant, CalibrationSample: pt})
		}
	}
	s.mu.RUnlock()

	sort.Slice(f.Paths, func(i, j int) bool {
		if f.Paths[i].Tenant != f.Paths[j].Tenant {
			return f.Paths[i].Tenant < f.Paths[j].Tenant
		}
		return f.Paths[i].ID < f.Paths[j].ID
	})
	sort.Slice(f.Posture, func(i, j int) bool {
		if f.Posture[i].Tenant != f.Posture[j].Tenant {
			return f.Posture[i].Tenant < f.Posture[j].Tenant
		}
		return f.Posture[i].At.Before(f.Posture[j].At)
	})
	sort.Slice(f.Calibration, func(i, j int) bool {
		if f.Calibration[i].Tenant != f.Calibration[j].Tenant {
			return f.Calibration[i].Tenant < f.Calibration[j].Tenant
		}
		return f.Calibration[i].At.Before(f.Calibration[j].At)
	})

	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if b, err = s.sealer.Seal(b); err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	// Unique temp name (not a shared "<path>.tmp") so two concurrent writers can't
	// corrupt each other's partial write; the rename is atomic and the last
	// consistent snapshot wins.
	tf, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	if _, err := tf.Write(b); err != nil {
		tf.Close()
		os.Remove(tmp)
		return err
	}
	if err := tf.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.path)
}
