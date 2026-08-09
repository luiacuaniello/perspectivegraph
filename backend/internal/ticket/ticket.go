// Package ticket closes the action loop's last mile: a finding only matters once
// someone owns fixing it. It turns an attack path into a tracked, owned ticket -
// recorded locally (the system of record for "who's on this and is it done") and
// optionally dispatched to an external tracker (Jira/GitHub/SOAR) via webhook.
//
// It deliberately mirrors internal/suppress (file-backed, per-tenant, atomic
// writes, nil-safe) plus internal/notify's webhook dispatch - one open ticket per
// path at a time, so the dashboard can show "ticketed · owner" and close it.
package ticket

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// Status is a ticket's lifecycle state.
type Status string

const (
	StatusOpen   Status = "open"
	StatusClosed Status = "closed"
)

// Ticket is one owned unit of remediation work for an attack path.
type Ticket struct {
	ID          string     `json:"id"`
	Tenant      string     `json:"tenant"`
	PathID      string     `json:"path_id"`
	Title       string     `json:"title"`
	Route       string     `json:"route,omitempty"` // human-readable path, for context
	Owner       string     `json:"owner"`           // accountable human/team - required
	Status      Status     `json:"status"`
	ExternalURL string     `json:"external_url,omitempty"` // set when an external tracker echoes one back
	CreatedAt   time.Time  `json:"created_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
}

var (
	ErrMissingPathID = errors.New("ticket: path id required")
	ErrMissingOwner  = errors.New("ticket: owner required")
	ErrNotFound      = errors.New("ticket: not found")
)

// Store is an in-memory, optionally file-backed set of tickets, isolated per
// tenant and safe for concurrent use. A nil *Store is a valid no-op. When a
// webhook URL is set, creating a ticket also POSTs it to that external tracker.
type Store struct {
	mu         sync.RWMutex
	path       string
	webhookURL string
	httpClient *http.Client
	byTenant   map[string]map[string]Ticket // tenant -> id -> ticket
	now        func() time.Time
	sealer     cryptostore.Sealer
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

// Tickets is what the API depends on, so a deployment can keep remediation work in a
// file (one replica) or in Postgres (many) without the handler knowing which.
//
// Reads take a context and return an error for the same reason the suppression store's
// do: an empty list read from a broken database looks exactly like "no outstanding
// work", and a team would re-open tickets that already exist.
type Tickets interface {
	Create(ctx context.Context, t Ticket) (Ticket, error)
	Close(ctx context.Context, tenant, id string) (Ticket, error)
	List(ctx context.Context, tenant string) ([]Ticket, error)
	OpenForPath(ctx context.Context, tenant, pathID string) (Ticket, bool, error)
	Persistent() bool
	Dispatches() bool
}

// validate enforces the accountable minimum, shared by both backends so a ticket one
// accepts cannot be one the other would refuse.
func validate(t Ticket) error {
	if t.PathID == "" {
		return ErrMissingPathID
	}
	if t.Owner == "" {
		return ErrMissingOwner
	}
	return nil
}

// New builds a store. path enables file persistence; webhookURL enables external
// dispatch (empty → dry-run, the ticket is logged and tracked locally only).
func New(path, webhookURL string, opts ...Option) (*Store, error) {
	s := &Store{
		path:       path,
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		byTenant:   map[string]map[string]Ticket{},
		now:        time.Now,
		sealer:     cryptostore.Nop(),
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

// Persistent reports whether tickets are file-backed.
func (s *Store) Persistent() bool { return s != nil && s.path != "" }

// Dispatches reports whether tickets are pushed to an external tracker.
func (s *Store) Dispatches() bool { return s != nil && s.webhookURL != "" }

func tenantKey(t string) string {
	if t == "" {
		return "default"
	}
	return t
}

// Create opens a ticket for a path. If an open ticket already exists for that
// path it is returned unchanged (idempotent - one open ticket per path), so a
// double-click can't fork the work. The new ticket is dispatched to the external
// tracker when one is configured.
func (s *Store) Create(ctx context.Context, t Ticket) (Ticket, error) {
	if s == nil {
		return Ticket{}, errors.New("ticket: store not configured")
	}
	if t.PathID == "" {
		return Ticket{}, ErrMissingPathID
	}
	if t.Owner == "" {
		return Ticket{}, ErrMissingOwner
	}
	t.Tenant = tenantKey(t.Tenant)

	s.mu.Lock()
	if existing, ok := s.openForPath(t.Tenant, t.PathID); ok {
		s.mu.Unlock()
		return existing, nil
	}
	t.ID = "tk-" + randHex()
	t.Status = StatusOpen
	t.CreatedAt = s.now().UTC()
	t.ClosedAt = nil
	if t.Title == "" {
		t.Title = "Remediate attack path " + t.PathID
	}
	if s.byTenant[t.Tenant] == nil {
		s.byTenant[t.Tenant] = map[string]Ticket{}
	}
	s.byTenant[t.Tenant][t.ID] = t
	s.mu.Unlock()

	dispatchTicket(ctx, s.webhookURL, t)
	if err := s.persist(); err != nil {
		return Ticket{}, err
	}
	return t, nil
}

// Close marks a ticket done (the path was remediated).
func (s *Store) Close(_ context.Context, tenant, id string) (Ticket, error) {
	if s == nil {
		return Ticket{}, errors.New("ticket: store not configured")
	}
	tenant = tenantKey(tenant)
	s.mu.Lock()
	m := s.byTenant[tenant]
	t, ok := m[id]
	if !ok {
		s.mu.Unlock()
		return Ticket{}, ErrNotFound
	}
	t.Status = StatusClosed
	closed := s.now().UTC()
	t.ClosedAt = &closed
	m[id] = t
	s.mu.Unlock()

	if err := s.persist(); err != nil {
		return Ticket{}, err
	}
	return t, nil
}

// List returns a tenant's tickets, newest first.
func (s *Store) List(_ context.Context, tenant string) ([]Ticket, error) {
	if s == nil {
		return nil, nil
	}
	tenant = tenantKey(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Ticket, 0, len(s.byTenant[tenant]))
	for _, t := range s.byTenant[tenant] {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// OpenForPath returns the open ticket for a path, if any - what the dashboard
// reads to show a "ticketed" badge.
func (s *Store) OpenForPath(_ context.Context, tenant, pathID string) (Ticket, bool, error) {
	if s == nil {
		return Ticket{}, false, nil
	}
	tenant = tenantKey(tenant)
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.openForPath(tenant, pathID)
	return t, ok, nil
}

// openForPath assumes the caller holds the lock.
func (s *Store) openForPath(tenant, pathID string) (Ticket, bool) {
	for _, t := range s.byTenant[tenant] {
		if t.PathID == pathID && t.Status == StatusOpen {
			return t, true
		}
	}
	return Ticket{}, false
}

// dispatch POSTs a newly created ticket to the external tracker, or logs it in
// dry-run. Best-effort: a tracker outage never fails the local create.
// dispatchTicket posts a newly created ticket to the configured webhook. Shared by both
// backends: where the ticket is stored has nothing to do with who is told about it.
func dispatchTicket(ctx context.Context, webhookURL string, t Ticket) {
	dispatchWith(ctx, dispatchClient, webhookURL, t)
}

// dispatchClient is the shared outbound client. A ticket webhook must never be able to
// hold a request handler open, so the timeout is short and explicit.
var dispatchClient = &http.Client{Timeout: 10 * time.Second}

func dispatchWith(ctx context.Context, client *http.Client, webhookURL string, t Ticket) {
	if webhookURL == "" {
		slog.Info("ticket created (dry-run - set TICKET_WEBHOOK_URL to dispatch)",
			"id", t.ID, "path", t.PathID, "owner", t.Owner)
		return
	}
	body, err := json.Marshal(t)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("ticket dispatch failed (tracked locally)", "id", t.ID, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Warn("ticket dispatch rejected (tracked locally)", "id", t.ID, "status", resp.StatusCode)
	}
}

func randHex() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ── persistence ─────────────────────────────────────────────────────

type fileShape struct {
	Tickets []Ticket `json:"tickets"`
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
		return fmt.Errorf("ticket: decrypt %s: %w", s.path, err)
	}
	var f fileShape
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("ticket: parse %s: %w", s.path, err)
	}
	for _, t := range f.Tickets {
		if s.byTenant[t.Tenant] == nil {
			s.byTenant[t.Tenant] = map[string]Ticket{}
		}
		s.byTenant[t.Tenant][t.ID] = t
	}
	return nil
}

func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	var f fileShape
	for _, m := range s.byTenant {
		for _, t := range m {
			f.Tickets = append(f.Tickets, t)
		}
	}
	s.mu.RUnlock()
	sort.Slice(f.Tickets, func(i, j int) bool {
		if f.Tickets[i].Tenant != f.Tickets[j].Tenant {
			return f.Tickets[i].Tenant < f.Tickets[j].Tenant
		}
		return f.Tickets[i].ID < f.Tickets[j].ID
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
