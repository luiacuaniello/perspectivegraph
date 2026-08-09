package suppress

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// PGStore keeps suppressions in PostgreSQL, so every replica sees the same triage
// decisions.
//
// This is what removes the single-replica ceiling. The file store holds its records in
// memory and writes the whole set out on each change, which is correct for exactly one
// writer and silently wrong for two: replica A's suppression is invisible to replica B,
// so the same path is on the board for half the users and hidden for the others, and the
// last writer's file quietly erases the other's decisions.
//
// There is no in-process cache here on purpose. A cache would restore precisely the
// staleness this exists to remove - and these are small rows read a few times a minute,
// not a hot path worth risking correctness for.
type PGStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewPG builds a Postgres-backed store. The caller owns the *sql.DB, because the same
// pool serves the graph and the other governance stores - one pool per process, not one
// per store.
func NewPG(db *sql.DB) (*PGStore, error) {
	if db == nil {
		return nil, errors.New("suppress: nil database handle")
	}
	return &PGStore{db: db, now: time.Now}, nil
}

// Persistent is always true here: unlike the file store, which reports false when it was
// given no path and is quietly in-memory, a database-backed store is durable by
// definition.
func (p *PGStore) Persistent() bool { return p != nil && p.db != nil }

// Put stores or replaces a suppression.
//
// The upsert is what makes re-suppressing an already-suppressed path work rather than
// fail on the primary key - an analyst changing the reason or extending the expiry is
// the ordinary case, not an error.
func (p *PGStore) Put(ctx context.Context, r Record) (Record, error) {
	if p == nil || p.db == nil {
		return Record{}, errors.New("suppress: store not configured")
	}
	r, err := normalize(r, p.now)
	if err != nil {
		return Record{}, err
	}

	const q = `
		INSERT INTO suppressions (tenant, path_id, reason, owner, note, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant, path_id) DO UPDATE SET
			reason = EXCLUDED.reason, owner = EXCLUDED.owner, note = EXCLUDED.note,
			created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at`
	if _, err := p.db.ExecContext(ctx, q,
		r.Tenant, r.PathID, string(r.Reason), r.Owner, r.Note, r.CreatedAt, r.ExpiresAt); err != nil {
		return Record{}, fmt.Errorf("suppress: put %s/%s: %w", r.Tenant, r.PathID, err)
	}
	return r, nil
}

// Delete un-suppresses a path. Deleting one that is not there is not an error: the
// desired end state is reached either way, and on several replicas the other one may
// simply have got there first.
func (p *PGStore) Delete(ctx context.Context, tenant, pathID string) error {
	if p == nil || p.db == nil {
		return errors.New("suppress: store not configured")
	}
	_, err := p.db.ExecContext(ctx,
		`DELETE FROM suppressions WHERE tenant = $1 AND path_id = $2`, tenantKey(tenant), pathID)
	if err != nil {
		return fmt.Errorf("suppress: delete %s/%s: %w", tenant, pathID, err)
	}
	return nil
}

// Get returns a suppression only while it is in force. An expired one reads as absent,
// because the path is active again - the row is kept so the board can still show that
// the decision was made and has lapsed.
func (p *PGStore) Get(ctx context.Context, tenant, pathID string) (Record, bool, error) {
	if p == nil || p.db == nil {
		return Record{}, false, errors.New("suppress: store not configured")
	}
	const q = `
		SELECT tenant, path_id, reason, owner, note, created_at, expires_at
		FROM suppressions WHERE tenant = $1 AND path_id = $2`
	r, err := scanOne(p.db.QueryRowContext(ctx, q, tenantKey(tenant), pathID))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Record{}, false, nil
	case err != nil:
		return Record{}, false, fmt.Errorf("suppress: get %s/%s: %w", tenant, pathID, err)
	}
	if r.Expired(p.now()) {
		return Record{}, false, nil
	}
	return r, true, nil
}

// List returns every suppression for a tenant, expired ones included, newest first - the
// triage board shows lapsed decisions so an analyst can see what was let back on.
func (p *PGStore) List(ctx context.Context, tenant string) ([]Record, error) {
	if p == nil || p.db == nil {
		return nil, errors.New("suppress: store not configured")
	}
	const q = `
		SELECT tenant, path_id, reason, owner, note, created_at, expires_at
		FROM suppressions WHERE tenant = $1 ORDER BY created_at DESC`
	rows, err := p.db.QueryContext(ctx, q, tenantKey(tenant))
	if err != nil {
		return nil, fmt.Errorf("suppress: list %s: %w", tenant, err)
	}
	defer func() { _ = rows.Close() }()

	var out []Record
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("suppress: list %s: %w", tenant, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveSet returns the in-force suppressions keyed by path id, for O(1) decoration of a
// path list. Expiry is evaluated by the DATABASE rather than here, so every replica
// agrees on what has lapsed even when their clocks do not.
func (p *PGStore) ActiveSet(ctx context.Context, tenant string) (map[string]Record, error) {
	if p == nil || p.db == nil {
		return nil, errors.New("suppress: store not configured")
	}
	const q = `
		SELECT tenant, path_id, reason, owner, note, created_at, expires_at
		FROM suppressions
		WHERE tenant = $1 AND (expires_at IS NULL OR expires_at > now())`
	rows, err := p.db.QueryContext(ctx, q, tenantKey(tenant))
	if err != nil {
		return nil, fmt.Errorf("suppress: active set %s: %w", tenant, err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]Record{}
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("suppress: active set %s: %w", tenant, err)
		}
		out[r.PathID] = r
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanOne(row scanner) (Record, error) { return scanRow(row) }

func scanRow(row scanner) (Record, error) {
	var (
		r      Record
		reason string
		expiry sql.NullTime
	)
	if err := row.Scan(&r.Tenant, &r.PathID, &reason, &r.Owner, &r.Note, &r.CreatedAt, &expiry); err != nil {
		return Record{}, err
	}
	r.Reason = Reason(reason)
	if expiry.Valid {
		e := expiry.Time.UTC()
		r.ExpiresAt = &e
	}
	r.CreatedAt = r.CreatedAt.UTC()
	return r, nil
}
