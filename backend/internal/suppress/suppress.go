// Package suppress is the triage/suppression loop: an analyst's decision to take
// a specific attack path off the active board — because the risk is accepted, the
// correlation is a false positive, a compensating control already covers it, or
// it duplicates another path — without deleting the underlying graph data.
//
// A suppression is keyed by attack-path id (stable across passes for the same
// seed→crown-jewel pair) and tenant, and always carries an accountable owner and
// a reason; it may carry an expiry, after which the path automatically returns to
// the active set (so "accept for 30 days" can't silently become "accept forever").
// The store is the system of record for who decided what, and why — the audit of
// the tool's own findings that a security tool must have.
package suppress

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// Reason is the closed set of triage dispositions. Keeping it closed makes the
// suppression board reportable ("show me everything accepted-as-risk") and stops
// free-text from hiding the actual disposition.
type Reason string

const (
	ReasonAcceptRisk        Reason = "accept-risk"        // a human accepts this exposure, eyes open
	ReasonFalsePositive     Reason = "false-positive"     // the path/correlation isn't real
	ReasonMitigatingControl Reason = "mitigating-control" // a control outside the graph already blocks it
	ReasonDuplicate         Reason = "duplicate"          // tracked under another path/ticket
)

var validReasons = map[Reason]bool{
	ReasonAcceptRisk: true, ReasonFalsePositive: true,
	ReasonMitigatingControl: true, ReasonDuplicate: true,
}

// ValidReason reports whether r is one of the allowed dispositions.
func ValidReason(r Reason) bool { return validReasons[r] }

// tenantKey maps an empty tenant to the default, matching how the analyzer and
// API key per-tenant state, so a suppression written under one is found under the
// other. (The API passes the same caller tenant to both.)
func tenantKey(t string) string {
	if t == "" {
		return auth.DefaultTenant
	}
	return t
}

// Record is one triage decision about one attack path.
type Record struct {
	PathID    string     `json:"path_id"`
	Tenant    string     `json:"tenant"`
	Reason    Reason     `json:"reason"`
	Owner     string     `json:"owner"`          // accountable human/team — required
	Note      string     `json:"note,omitempty"` // optional free-text justification
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = no expiry
}

// Active reports whether the suppression is in force at t (not yet expired).
func (r Record) Active(t time.Time) bool {
	return r.ExpiresAt == nil || r.ExpiresAt.After(t)
}

// Expired reports whether the suppression has lapsed at t.
func (r Record) Expired(t time.Time) bool { return !r.Active(t) }

var (
	// ErrInvalidReason is returned by Put for a reason outside the allowed set.
	ErrInvalidReason = errors.New("suppress: invalid reason")
	// ErrMissingPathID / ErrMissingOwner enforce the minimum accountable record.
	ErrMissingPathID = errors.New("suppress: path id required")
	ErrMissingOwner  = errors.New("suppress: owner required")
)

// Store is an in-memory, optionally file-backed set of suppressions, isolated per
// tenant. It is safe for concurrent use. A nil *Store is a valid no-op store, so
// callers never have to nil-check (every path is simply "not suppressed").
type Store struct {
	mu   sync.RWMutex
	path string // "" = in-memory only
	// tenant -> pathID -> record
	byTenant map[string]map[string]Record
	now      func() time.Time // injectable clock for tests
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

// New builds a store. When path is non-empty it is loaded from disk (a missing
// file is fine — it's created on first write) and every mutation is persisted.
func New(path string, opts ...Option) (*Store, error) {
	s := &Store{
		path:     path,
		byTenant: map[string]map[string]Record{},
		now:      time.Now,
		sealer:   cryptostore.Nop(),
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

// Persistent reports whether the store is backed by a file.
func (s *Store) Persistent() bool { return s != nil && s.path != "" }

// Put stores (creating or replacing) a suppression. It validates the reason and
// the accountable fields, stamps CreatedAt when unset, normalizes the tenant, and
// persists. A zero *Store is a no-op error so misconfiguration is loud.
func (s *Store) Put(r Record) (Record, error) {
	if s == nil {
		return Record{}, errors.New("suppress: store not configured")
	}
	if r.PathID == "" {
		return Record{}, ErrMissingPathID
	}
	if r.Owner == "" {
		return Record{}, ErrMissingOwner
	}
	if !ValidReason(r.Reason) {
		return Record{}, fmt.Errorf("%w: %q", ErrInvalidReason, r.Reason)
	}
	r.Tenant = tenantKey(r.Tenant)
	if r.CreatedAt.IsZero() {
		r.CreatedAt = s.now().UTC()
	} else {
		r.CreatedAt = r.CreatedAt.UTC()
	}
	if r.ExpiresAt != nil {
		e := r.ExpiresAt.UTC()
		r.ExpiresAt = &e
	}

	s.mu.Lock()
	if s.byTenant[r.Tenant] == nil {
		s.byTenant[r.Tenant] = map[string]Record{}
	}
	s.byTenant[r.Tenant][r.PathID] = r
	s.mu.Unlock()

	if err := s.persist(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// Delete removes a suppression (un-suppresses the path). Removing one that does
// not exist is not an error — the desired end state is reached either way.
func (s *Store) Delete(tenant, pathID string) error {
	if s == nil {
		return errors.New("suppress: store not configured")
	}
	tenant = tenantKey(tenant)
	s.mu.Lock()
	if m := s.byTenant[tenant]; m != nil {
		delete(m, pathID)
	}
	s.mu.Unlock()
	return s.persist()
}

// Get returns the suppression for a path if one exists and is still in force.
// Expired suppressions are reported as absent — the path is active again.
func (s *Store) Get(tenant, pathID string) (Record, bool) {
	if s == nil {
		return Record{}, false
	}
	tenant = tenantKey(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byTenant[tenant][pathID]
	if !ok || r.Expired(s.now()) {
		return Record{}, false
	}
	return r, true
}

// List returns every suppression for a tenant — including expired ones, so the
// triage board can show lapsed decisions — newest first.
func (s *Store) List(tenant string) []Record {
	if s == nil {
		return nil
	}
	tenant = tenantKey(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.byTenant[tenant]))
	for _, r := range s.byTenant[tenant] {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ActiveSet returns the in-force suppressions for a tenant keyed by path id, for
// cheap O(1) decoration of a path list. Expired entries are excluded.
func (s *Store) ActiveSet(tenant string) map[string]Record {
	if s == nil {
		return nil
	}
	tenant = tenantKey(tenant)
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Record, len(s.byTenant[tenant]))
	for id, r := range s.byTenant[tenant] {
		if r.Active(now) {
			out[id] = r
		}
	}
	return out
}

// ── persistence ─────────────────────────────────────────────────────

// fileShape is the on-disk format: a flat, human-diffable list of records.
type fileShape struct {
	Records []Record `json:"records"`
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // first run — nothing to load
	}
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if b, err = s.sealer.Open(b); err != nil {
		return fmt.Errorf("suppress: decrypt %s: %w", s.path, err)
	}
	var f fileShape
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("suppress: parse %s: %w", s.path, err)
	}
	for _, r := range f.Records {
		if s.byTenant[r.Tenant] == nil {
			s.byTenant[r.Tenant] = map[string]Record{}
		}
		s.byTenant[r.Tenant][r.PathID] = r
	}
	return nil
}

// persist writes the whole store atomically (temp file + rename) with owner-only
// permissions — the suppression board reveals which exposures are knowingly left
// open, so it is treated as sensitive.
func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	var f fileShape
	for _, m := range s.byTenant {
		for _, r := range m {
			f.Records = append(f.Records, r)
		}
	}
	s.mu.RUnlock()
	sort.Slice(f.Records, func(i, j int) bool {
		if f.Records[i].Tenant != f.Records[j].Tenant {
			return f.Records[i].Tenant < f.Records[j].Tenant
		}
		return f.Records[i].PathID < f.Records[j].PathID
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
