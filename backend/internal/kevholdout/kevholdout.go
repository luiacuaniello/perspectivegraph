// Package kevholdout calibrates the engine's per-CVE hop probability against reality,
// without a red team, by making it forecast something it cannot already see.
//
// The engine derives a CVE hop's traversal probability from KEV and EPSS
// (threatintel.EdgeProbability). Grading that number against KEV membership *today*
// would be circular: a CVE in KEV is assigned 0.95 by the formula itself, so the
// measurement would score the formula against its own input and report an excellent
// Brier that means nothing.
//
// The holdout breaks the circle with time. A forecast is SEALED for a CVE that is not
// in KEV at that moment - recording what the engine believed using only the data of
// that day - and is graded only after a fixed window, against an event that had not
// happened when the forecast was made: did this CVE enter KEV during the window? That
// is a genuine out-of-sample prediction, and it is the same construction FIRST uses to
// evaluate EPSS itself.
//
// Two limits are structural and are reported rather than papered over:
//
//   - The graded event is NARROWER than the modelled one. EPSS estimates "exploitation
//     activity is observed in the wild"; KEV entry additionally requires CISA to confirm
//     and catalogue it, which is rarer and lags. So absolute level will look
//     overconfident whatever the engine does. The calibration track therefore publishes
//     no recommended scale (see validation.Calibration.Edge) - what survives the
//     mismatch is discrimination: do higher-scored CVEs enter KEV more often.
//   - Nothing can be graded retroactively, because a forecast has to be sealed before
//     its outcome exists. The dataset starts empty and fills after one window.
package kevholdout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/threatintel"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// DefaultWindow matches the horizon EPSS itself forecasts over, so the sealed
// prediction and the graded question span the same 30 days.
const DefaultWindow = 30 * 24 * time.Hour

// Snapshot is one sealed forecast: what the engine predicted for a CVE, on the
// evidence available at SealedAt, before the outcome existed.
type Snapshot struct {
	CVE       string    `json:"cve"`
	Predicted float64   `json:"predicted"` // threatintel.EdgeProbability at seal time
	EPSS      float64   `json:"epss"`      // the evidence behind it, kept for auditing
	Basis     string    `json:"basis"`     // weight basis at seal time (epss|cvss|…)
	SealedAt  time.Time `json:"sealed_at"`
	Tenant    string    `json:"tenant"`
}

// due reports whether this snapshot has reached its grading date.
func (s Snapshot) due(now time.Time, window time.Duration) bool {
	return !now.Before(s.SealedAt.Add(window))
}

// Store holds sealed forecasts until they mature. It is deliberately a plain JSON
// file like the validation store: the dataset is small (one row per CVE per window)
// and has to survive restarts, or the window resets forever and nothing is ever graded.
type Store struct {
	mu   sync.Mutex
	path string
	byID map[string]Snapshot // key: tenant\x00cve - one open forecast per CVE at a time
	now  func() time.Time
}

// NewStore opens (or creates) the snapshot store. An empty path keeps it in memory,
// which is only useful for tests: a process that restarts loses every pending forecast
// and can never complete a window.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, byID: map[string]Snapshot{}, now: time.Now}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("kevholdout: create dir: %w", err)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- operator-configured KEV_HOLDOUT_PATH, not attacker-controlled
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kevholdout: read %s: %w", path, err)
	}
	var rows []Snapshot
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("kevholdout: parse %s: %w", path, err)
	}
	for _, r := range rows {
		s.byID[key(r.Tenant, r.CVE)] = r
	}
	return s, nil
}

func key(tenant, cve string) string { return tenant + "\x00" + cve }

// Pending returns the sealed forecasts, oldest first.
func (s *Store) Pending() []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Snapshot, 0, len(s.byID))
	for _, v := range s.byID {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SealedAt.Before(out[j].SealedAt) })
	return out
}

// seal records a forecast unless one is already open for that CVE. Re-sealing an open
// forecast would restart its clock on every pass and nothing would ever mature.
func (s *Store) seal(snap Snapshot) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(snap.Tenant, snap.CVE)
	if _, exists := s.byID[k]; exists {
		return false
	}
	s.byID[k] = snap
	return true
}

func (s *Store) drop(tenant, cve string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, key(tenant, cve))
}

// flush persists the open forecasts. Called after a pass rather than per write.
func (s *Store) flush() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	rows := make([]Snapshot, 0, len(s.byID))
	for _, v := range s.byID {
		rows = append(rows, v)
	}
	s.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].CVE < rows[j].CVE })
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Sink is the part of the validation store this package needs: somewhere to file a
// matured verdict. Narrowed to an interface so the holdout can be tested without one.
type Sink interface {
	Put(context.Context, validation.Record) (validation.Record, error)
}

// Holdout is the sealed-forecast store the runner needs. Narrowed to an interface so a
// deployment can keep the seals in a file (one replica) or in Postgres (many) - and so
// the runner can be tested without either.
type Holdout interface {
	Pending() []Snapshot
	seal(Snapshot) bool
	drop(tenant, cve string)
	flush() error
}

// Runner seals forecasts and grades the ones that have come due.
type Runner struct {
	intel  threatintel.Source
	store  Holdout
	sink   Sink
	window time.Duration
	now    func() time.Time
	log    *slog.Logger
}

// NewRunner wires a holdout run. window <= 0 uses DefaultWindow.
func NewRunner(intel threatintel.Source, store Holdout, sink Sink, window time.Duration, log *slog.Logger) *Runner {
	if window <= 0 {
		window = DefaultWindow
	}
	if log == nil {
		log = slog.Default()
	}
	return &Runner{intel: intel, store: store, sink: sink, window: window, now: time.Now, log: log}
}

// Result reports what one pass did, for logging and tests.
type Result struct {
	Sealed    int // new forecasts opened
	Graded    int // forecasts that came due and were filed as verdicts
	Exploited int // of those, how many had entered KEV
}

// Run performs one pass over cves: grade whatever has matured, then seal new forecasts.
//
// Grading happens FIRST so that a CVE whose forecast just closed can immediately open a
// fresh one in the same pass; sealing first would grade a forecast against intel fetched
// after it was re-sealed.
func (r *Runner) Run(ctx context.Context, tenant string, cves []string) (Result, error) {
	var res Result
	if r == nil || r.intel == nil || !r.intel.Enabled() || len(cves) == 0 {
		return res, nil
	}
	now := r.now()

	// One fetch covers both phases: the due forecasts need today's KEV membership, and
	// the new ones need today's evidence.
	due := map[string]Snapshot{}
	for _, snap := range r.store.Pending() {
		if snap.Tenant == tenant && snap.due(now, r.window) {
			due[snap.CVE] = snap
		}
	}
	want := make([]string, 0, len(cves)+len(due))
	want = append(want, cves...)
	for cve := range due {
		want = append(want, cve)
	}
	intel := r.intel.Scores(ctx, dedupe(want))

	// ── grade what has come due ───────────────────────────────────────────────
	for cve, snap := range due {
		in := intel[cve]
		outcome := validation.Refuted
		if in.KEV {
			outcome = validation.Confirmed
			res.Exploited++
		}
		rec := validation.Record{
			Tenant:         tenant,
			Outcome:        outcome,
			Scope:          validation.ScopeEdge,
			Source:         "kev-holdout",
			Route:          cve,
			PredictedScore: snap.Predicted,
			WeightBasis:    snap.Basis,
			TestedAt:       now,
			Evidence: fmt.Sprintf("sealed %s, graded after %s: %s KEV at grading time",
				snap.SealedAt.UTC().Format(time.RFC3339), r.window, boolWord(in.KEV)),
		}
		if _, err := r.sink.Put(ctx, rec); err != nil {
			// A failed file must not drop the forecast: leaving it pending means the
			// next pass retries rather than silently losing the only labelled sample.
			r.log.Warn("kev holdout: filing verdict failed, forecast left pending", "cve", cve, "err", err)
			continue
		}
		r.store.drop(tenant, cve)
		res.Graded++
	}

	// ── seal new forecasts ────────────────────────────────────────────────────
	for _, cve := range cves {
		in, ok := intel[cve]
		if !ok {
			continue // no intel: nothing to forecast from
		}
		// A CVE already in KEV has no forecast left to make - the event has happened.
		// Sealing it would re-import the circularity this package exists to avoid.
		if in.KEV {
			continue
		}
		if in.EPSS <= 0 {
			continue // no evidence: the prediction would be the caller's fallback, not the model's
		}
		if r.store.seal(Snapshot{
			CVE:       cve,
			Predicted: in.EdgeProbability(0),
			EPSS:      in.EPSS,
			Basis:     in.Basis(),
			SealedAt:  now,
			Tenant:    tenant,
		}) {
			res.Sealed++
		}
	}

	if err := r.store.flush(); err != nil {
		return res, fmt.Errorf("kevholdout: persist: %w", err)
	}
	return res, nil
}

func boolWord(b bool) string {
	if b {
		return "in"
	}
	return "not in"
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
