package secwatch

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"
)

// refreshEvery is how often the cached view of durable lockouts is rebuilt.
//
// Locked is called on EVERY pre-authentication request, so it may not touch the
// database: a credential-stuffing run would otherwise be a way to make the tool hammer
// its own store, which is the amplifier shape this project refuses elsewhere (see the
// audit log's queue). A cached snapshot keeps the request path a map lookup.
//
// The cost is staleness in one direction: a lockout set by ANOTHER replica takes up to
// this long to be seen here. Lockouts last minutes and the detection window is seconds,
// so the attacker's gain is a fraction of one window against one replica - while a
// lockout set by this process is enforced immediately from memory, with no wait.
const refreshEvery = 30 * time.Second

// PGTrips stores lockouts in PostgreSQL so they survive a restart and are shared by
// every replica.
type PGTrips struct {
	db  *sql.DB
	now func() time.Time

	mu     sync.RWMutex
	locked map[string]time.Time
	loaded time.Time
}

// NewPGTrips builds the store and loads the lockouts already in force, so a process
// that has just restarted enforces them from its first request rather than from its
// first refresh.
func NewPGTrips(ctx context.Context, db *sql.DB) (*PGTrips, error) {
	s := &PGTrips{db: db, now: time.Now, locked: map[string]time.Time{}}
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Trip records a lockout. Failures are logged rather than returned: the caller is
// middleware handling a request that is already being denied, and a store that is
// unreachable must not turn a denial into a 500. The in-memory lockout still holds for
// this process, so the control degrades to exactly what it was before this table.
func (s *PGTrips) Trip(key string, until time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_lockout (key, locked_until) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE
		SET locked_until = GREATEST(auth_lockout.locked_until, EXCLUDED.locked_until)`,
		key, until.UTC()); err != nil {
		slog.Error("auth lockout: could not persist; it holds on this replica only", "err", err)
		return
	}
	s.mu.Lock()
	if cur, ok := s.locked[key]; !ok || until.After(cur) {
		s.locked[key] = until
	}
	s.mu.Unlock()
}

// Locked reads the cached snapshot, rebuilding it when it has aged out.
func (s *PGTrips) Locked(key string) bool {
	s.mu.RLock()
	until, ok := s.locked[key]
	stale := s.now().Sub(s.loaded) > refreshEvery
	s.mu.RUnlock()

	if stale {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.refresh(ctx); err != nil {
			// Keep serving the snapshot already held: an unreachable database must not
			// unlock everyone, and must not fail the request either.
			slog.Warn("auth lockout: refresh failed, serving the cached view", "err", err)
		}
		s.mu.RLock()
		until, ok = s.locked[key]
		s.mu.RUnlock()
	}
	return ok && s.now().Before(until)
}

// refresh rebuilds the snapshot from the lockouts still in force, and drops the expired
// rows so the table does not accumulate one per lockout ever taken.
func (s *PGTrips) refresh(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM auth_lockout WHERE locked_until < now()`); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT key, locked_until FROM auth_lockout`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	fresh := map[string]time.Time{}
	for rows.Next() {
		var (
			key   string
			until time.Time
		)
		if err := rows.Scan(&key, &until); err != nil {
			return err
		}
		fresh[key] = until
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.locked, s.loaded = fresh, s.now()
	s.mu.Unlock()
	return nil
}
