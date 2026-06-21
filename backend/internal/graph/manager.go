package graph

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// DefaultTenant is the tenant a single-tenant deployment (and any event with no
// tenant) maps to.
const DefaultTenant = "default"

// StoreFactory creates the backing store for a tenant (e.g. an Apache AGE graph
// named per-tenant, or a fresh in-memory store).
type StoreFactory func(ctx context.Context, tenant string) (Store, error)

// Manager owns one VersionedStore per tenant, created lazily on first use so a
// tenant's data is isolated in its own graph. It is safe for concurrent use.
type Manager struct {
	factory StoreFactory

	mu     sync.RWMutex
	stores map[string]*VersionedStore
}

// NewManager returns a manager and eagerly instantiates the default tenant so
// the analyzer and API have something to serve out of the box.
func NewManager(ctx context.Context, factory StoreFactory) (*Manager, error) {
	m := &Manager{factory: factory, stores: map[string]*VersionedStore{}}
	if _, err := m.For(ctx, DefaultTenant); err != nil {
		return nil, err
	}
	return m, nil
}

// For returns the store for a tenant, creating it on first reference. An empty
// tenant resolves to the default tenant.
func (m *Manager) For(ctx context.Context, tenant string) (*VersionedStore, error) {
	tenant = NormalizeTenant(tenant)

	m.mu.RLock()
	s := m.stores[tenant]
	m.mu.RUnlock()
	if s != nil {
		return s, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.stores[tenant]; s != nil { // double-check after acquiring write lock
		return s, nil
	}
	inner, err := m.factory(ctx, tenant)
	if err != nil {
		return nil, err
	}
	vs := NewVersionedStore(inner)
	m.stores[tenant] = vs
	return vs, nil
}

// Tenants lists the instantiated tenants, sorted.
func (m *Manager) Tenants() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.stores))
	for t := range m.stores {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Close closes every tenant store.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for _, s := range m.stores {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// NormalizeTenant lowercases and reduces a tenant id to [a-z0-9_], so it is safe
// to embed in a graph/index name; empty → DefaultTenant.
func NormalizeTenant(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return DefaultTenant
	}
	var b strings.Builder
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
