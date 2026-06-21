// Package leader provides single-leader election so that, when the backend runs
// with more than one replica, exactly one of them performs at-most-once external
// actions (drift webhooks, PR/MR comments). Every replica still computes attack
// paths locally to serve its own API reads — only the *side effects* are gated,
// so adding replicas scales reads without duplicating outbound notifications.
//
// Election uses a PostgreSQL session-scoped advisory lock: the holder is the
// leader, and if it dies the lock is released automatically, so another replica
// takes over on its next check (no external coordinator needed).
package leader

import (
	"context"
	"database/sql"
	"hash/fnv"
	"log/slog"
	"sync"

	_ "github.com/lib/pq"
)

// AlwaysLeader is the leader unconditionally — the correct elector for a
// single-process / in-memory deployment.
type AlwaysLeader struct{}

func (AlwaysLeader) IsLeader(context.Context) bool { return true }

// Postgres holds a session-scoped advisory lock on a dedicated connection; while
// it holds the lock it is the leader. A dropped connection releases the lock
// (failover), and the next IsLeader call tries to re-acquire it.
type Postgres struct {
	db  *sql.DB
	key int64

	mu   sync.Mutex
	conn *sql.Conn // the connection holding the advisory lock, while leader
}

// NewPostgres opens a small dedicated pool for the lock. role names the lock so
// different singletons (e.g. "analyzer") don't contend.
func NewPostgres(dsn, role string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	// One reserved connection holds the lock; a couple spare for re-acquire/ping.
	db.SetMaxOpenConns(3)
	h := fnv.New64a()
	_, _ = h.Write([]byte("perspectivegraph:leader:" + role))
	return &Postgres{db: db, key: int64(h.Sum64())}, nil // #nosec G115 -- advisory-lock key from a fixed FNV hash; any 64-bit pattern is valid
}

// IsLeader reports whether this process currently holds leadership, acquiring
// the lock if it is free.
func (p *Postgres) IsLeader(ctx context.Context) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Still holding it? Verify the connection is alive (a dropped one released
	// the lock server-side, so we must re-acquire).
	if p.conn != nil {
		if err := p.conn.PingContext(ctx); err == nil {
			return true
		}
		_ = p.conn.Close()
		p.conn = nil
	}

	conn, err := p.db.Conn(ctx)
	if err != nil {
		slog.Warn("leader: cannot get connection", "err", err)
		return false
	}
	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", p.key).Scan(&acquired); err != nil {
		slog.Warn("leader: advisory lock query failed", "err", err)
		_ = conn.Close()
		return false
	}
	if !acquired {
		_ = conn.Close() // another replica is the leader; release this connection
		return false
	}
	p.conn = conn // keep the connection (and thus the lock) for the session
	return true
}

// Close releases the lock (by closing its connection) and the pool.
func (p *Postgres) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
	return p.db.Close()
}
