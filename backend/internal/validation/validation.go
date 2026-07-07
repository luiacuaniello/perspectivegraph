// Package validation grounds the engine against reality. An attack-path model is
// a hypothesis until something tries to walk it; this is where a red-team or BAS
// platform (Caldera, AttackIQ, SafeBreach, Cymulate, …) - or a human - reports
// the verdict: "I tested this path, it's real" / "false positive, not traversable"
// / "partial", and crucially "you MISSED a real path I found".
//
// From those verdicts it computes the honest trust metric the tool otherwise
// lacks - precision and recall over the *validated* subset:
//
//	precision = confirmed / (confirmed + refuted)   // of surfaced+tested paths, how many were real
//	recall    = confirmed / (confirmed + missed)     // of real paths, how many we surfaced
//
// It is NOT a global precision/recall claim (that needs exhaustive ground truth);
// it is "here is the evidence on what was actually tested", which is the point.
package validation

import (
	"crypto/rand"
	"encoding/hex"
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

// Outcome is the closed set of validation verdicts.
type Outcome string

const (
	Confirmed Outcome = "confirmed" // path tested and exploitable end-to-end (true positive)
	Refuted   Outcome = "refuted"   // tested and NOT traversable - a false positive
	Partial   Outcome = "partial"   // partially traversable / inconclusive
	Missed    Outcome = "missed"    // a real path the tester found that the engine did NOT surface (false negative)
)

var validOutcomes = map[Outcome]bool{Confirmed: true, Refuted: true, Partial: true, Missed: true}

// ValidOutcome reports whether o is one of the allowed verdicts.
func ValidOutcome(o Outcome) bool { return validOutcomes[o] }

// Scope declares what a verdict validated, which fixes the quantity the calibration
// grades it against. A path-scoped verdict tested one specific surfaced path
// end-to-end, so it grades that path's score S(P). A target-scoped verdict tested
// whether a crown jewel was reached AT ALL, by any route - the event a BAS "I popped
// the jewel" run actually reports - so it grades the per-target compromise
// probability, not S(P). Grading S(P) against an any-route outcome conflates two
// different events and biases the report; the scope keeps each track honest.
type Scope string

const (
	ScopePath   Scope = "path"   // validated one specific surfaced path (grades S(P))
	ScopeTarget Scope = "target" // validated that a crown jewel was reached at all (grades compromise probability)
)

var validScopes = map[Scope]bool{ScopePath: true, ScopeTarget: true}

// ValidScope reports whether s is empty (⇒ path) or one of the allowed scopes.
func ValidScope(s Scope) bool { return s == "" || validScopes[s] }

// scopeOrDefault treats an unset scope as path - the historical default, so existing
// verdicts (recorded before scope existed) keep grading S(P).
func scopeOrDefault(s Scope) Scope {
	if s == "" {
		return ScopePath
	}
	return s
}

// Record is one validation verdict about a path. For "missed", PathID may be
// empty (the engine never surfaced it) and Route describes what was found.
type Record struct {
	ID       string    `json:"id"`
	PathID   string    `json:"path_id,omitempty"`
	Tenant   string    `json:"tenant"`
	Outcome  Outcome   `json:"outcome"`
	Source   string    `json:"source"`             // the BAS tool or tester - accountability
	Evidence string    `json:"evidence,omitempty"` // notes / a link to the run
	Route    string    `json:"route,omitempty"`    // human route, esp. for "missed"
	TestedAt time.Time `json:"tested_at"`
	// PredictedScore is the path's exploit-probability score S(P) at the moment the
	// verdict was recorded (captured server-side from the live analysis). It is what
	// turns a pile of verdicts into a *calibration* dataset: pairing the model's
	// predicted probability with the observed outcome lets us measure whether "0.8"
	// really fires ~80% of the time (see Calibration). Zero ⇒ unknown (the path was
	// no longer surfaced, or a pre-calibration record) and is excluded from the
	// calibration math. Omitted for "missed" verdicts (no surfaced path to score).
	PredictedScore float64 `json:"predicted_score,omitempty"`
	// Scope declares what this verdict validated (path vs target) and so which
	// prediction the calibration grades it against. Empty ⇒ path (historical default).
	Scope Scope `json:"scope,omitempty"`
	// PredictedCompromise is the model's predicted probability that this verdict's
	// crown-jewel target is reached AT ALL (by any route) - the per-target Monte Carlo
	// compromise probability, captured server-side at verdict time. It is what a
	// target-scoped verdict is graded against, distinct from the per-path PredictedScore.
	// Zero ⇒ unknown/not-captured and is excluded from the target-calibration math.
	PredictedCompromise float64 `json:"predicted_compromise,omitempty"`
	// Hops and CorrelatedHops are path-structure features captured server-side at
	// verdict time, so calibration can be *segmented* by them: if the model is
	// mis-scored specifically on long or correlated-hop paths, the error is structural
	// (the independence assumption / path length compounding) and points at a
	// correlation-aware model (#6) rather than a flat rescale.
	Hops           int  `json:"hops,omitempty"`
	CorrelatedHops bool `json:"correlated_hops,omitempty"`
	// WeightBasis is the path's weakest-evidence hop basis (kev|epss|cvss|severity|
	// heuristic|runtime), captured server-side at verdict time so calibration can be
	// recalibrated *per basis* - a bias structured by evidence provenance that a single
	// global monotone rescale cannot fix (P1).
	WeightBasis string `json:"weight_basis,omitempty"`
	// Detected is the operator's report of whether this (confirmed) attempt was caught
	// or blocked by a defense (EDR/WAF/SOC). nil = not reported. It is the evidence for
	// the *detection axis* (#7): if reachable paths are routinely detected, the score
	// over-predicts undetected impact and the model needs a P(reach ∧ ¬detect) term.
	Detected *bool `json:"detected,omitempty"`
}

// Metrics is the rolled-up, evidence-based trust summary for a tenant.
type Metrics struct {
	Confirmed int     `json:"confirmed"`
	Refuted   int     `json:"refuted"`
	Partial   int     `json:"partial"`
	Missed    int     `json:"missed"`
	Tested    int     `json:"tested"`    // confirmed + refuted + partial (paths surfaced and tested)
	Precision float64 `json:"precision"` // confirmed / (confirmed+refuted)
	Recall    float64 `json:"recall"`    // confirmed / (confirmed+missed)
	HasData   bool    `json:"has_data"`  // false ⇒ precision/recall are undefined
}

var (
	ErrInvalidOutcome = errors.New("validation: invalid outcome")
	ErrInvalidScope   = errors.New("validation: invalid scope (want path|target)")
	ErrMissingSource  = errors.New("validation: source required (who/what tested it)")
	ErrMissingPathID  = errors.New("validation: path id required (except for outcome=missed)")
	ErrNotFound       = errors.New("validation: not found")
)

// Store is an in-memory, optionally file-backed set of validation records,
// per-tenant and concurrency-safe. A nil *Store is a valid no-op.
type Store struct {
	mu       sync.RWMutex
	path     string
	byTenant map[string][]Record
	now      func() time.Time
	rnd      func() string
	sealer   cryptostore.Sealer
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

func New(path string, opts ...Option) (*Store, error) {
	s := &Store{path: path, byTenant: map[string][]Record{}, now: time.Now, rnd: randID, sealer: cryptostore.Nop()}
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

func (s *Store) Persistent() bool { return s != nil && s.path != "" }

func tenantKey(t string) string {
	if t == "" {
		return "default"
	}
	return t
}

// Put records a verdict. A confirmed/refuted/partial verdict references a real
// path (PathID) and replaces any prior verdict for that path (latest test wins);
// "missed" verdicts accumulate (each is a distinct false negative). Source is
// always required - a verdict without provenance isn't evidence.
func (s *Store) Put(r Record) (Record, error) {
	if s == nil {
		return Record{}, errors.New("validation: store not configured")
	}
	if !ValidOutcome(r.Outcome) {
		return Record{}, fmt.Errorf("%w: %q", ErrInvalidOutcome, r.Outcome)
	}
	if !ValidScope(r.Scope) {
		return Record{}, fmt.Errorf("%w: %q", ErrInvalidScope, r.Scope)
	}
	if r.Source == "" {
		return Record{}, ErrMissingSource
	}
	if r.Outcome != Missed && r.PathID == "" {
		return Record{}, ErrMissingPathID
	}
	r.Tenant = tenantKey(r.Tenant)
	if r.TestedAt.IsZero() {
		r.TestedAt = s.now().UTC()
	} else {
		r.TestedAt = r.TestedAt.UTC()
	}
	r.ID = s.rnd()

	s.mu.Lock()
	list := s.byTenant[r.Tenant]
	if r.Outcome != Missed {
		// One current verdict per (surfaced path, scope): a path may legitimately carry
		// both a path-scoped verdict (this exact path works) and a target-scoped one (the
		// jewel was reached at all) - they validate different events - so the replacement
		// key includes the scope; only a same-scope re-test supersedes.
		filtered := list[:0:0]
		for _, x := range list {
			if x.Outcome == Missed || x.PathID != r.PathID || scopeOrDefault(x.Scope) != scopeOrDefault(r.Scope) {
				filtered = append(filtered, x)
			}
		}
		list = filtered
	}
	s.byTenant[r.Tenant] = append(list, r)
	s.mu.Unlock()

	if err := s.persist(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// Delete removes a verdict by id.
func (s *Store) Delete(tenant, id string) error {
	if s == nil {
		return errors.New("validation: store not configured")
	}
	tenant = tenantKey(tenant)
	s.mu.Lock()
	list := s.byTenant[tenant]
	out := list[:0:0]
	found := false
	for _, x := range list {
		if x.ID == id {
			found = true
			continue
		}
		out = append(out, x)
	}
	s.byTenant[tenant] = out
	s.mu.Unlock()
	if !found {
		return ErrNotFound
	}
	return s.persist()
}

// Get returns the current verdict for a surfaced path, if any.
func (s *Store) Get(tenant, pathID string) (Record, bool) {
	if s == nil || pathID == "" {
		return Record{}, false
	}
	tenant = tenantKey(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.byTenant[tenant] {
		if r.Outcome != Missed && r.PathID == pathID {
			return r, true
		}
	}
	return Record{}, false
}

// List returns a tenant's verdicts, newest first.
func (s *Store) List(tenant string) []Record {
	if s == nil {
		return nil
	}
	tenant = tenantKey(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]Record(nil), s.byTenant[tenant]...)
	sort.Slice(out, func(i, j int) bool { return out[i].TestedAt.After(out[j].TestedAt) })
	return out
}

// Metrics rolls up precision/recall over the validated subset for a tenant.
func (s *Store) Metrics(tenant string) Metrics {
	if s == nil {
		return Metrics{}
	}
	tenant = tenantKey(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var m Metrics
	for _, r := range s.byTenant[tenant] {
		switch r.Outcome {
		case Confirmed:
			m.Confirmed++
		case Refuted:
			m.Refuted++
		case Partial:
			m.Partial++
		case Missed:
			m.Missed++
		}
	}
	m.Tested = m.Confirmed + m.Refuted + m.Partial
	if m.Confirmed+m.Refuted > 0 {
		m.Precision = float64(m.Confirmed) / float64(m.Confirmed+m.Refuted)
		m.HasData = true
	}
	if m.Confirmed+m.Missed > 0 {
		m.Recall = float64(m.Confirmed) / float64(m.Confirmed+m.Missed)
		m.HasData = true
	}
	return m
}

// ── persistence ─────────────────────────────────────────────────────

type fileShape struct {
	Records []Record `json:"records"`
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
		return fmt.Errorf("validation: decrypt %s: %w", s.path, err)
	}
	var f fileShape
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("validation: parse %s: %w", s.path, err)
	}
	for _, r := range f.Records {
		s.byTenant[r.Tenant] = append(s.byTenant[r.Tenant], r)
	}
	return nil
}

func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	var f fileShape
	for _, list := range s.byTenant {
		f.Records = append(f.Records, list...)
	}
	s.mu.RUnlock()
	sort.Slice(f.Records, func(i, j int) bool {
		if f.Records[i].Tenant != f.Records[j].Tenant {
			return f.Records[i].Tenant < f.Records[j].Tenant
		}
		return f.Records[i].ID < f.Records[j].ID
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

func randID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "vd-" + hex.EncodeToString(b[:])
}
