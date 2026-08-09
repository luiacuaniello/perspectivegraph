package ticket

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// PGStore keeps remediation tickets in PostgreSQL, so every replica sees the same work.
//
// The property that matters most here is not durability but the open-ticket check:
// Create refuses to open a second ticket for a path that already has one. With the file
// store that check reads a per-process map, so two replicas each see no ticket and each
// opens one - two engineers, two tickets, one path, and each believing the other's is
// theirs. Here the check is a query, so both replicas see the same answer.
type PGStore struct {
	db         *sql.DB
	webhookURL string
	now        func() time.Time
}

// NewPG builds a Postgres-backed ticket store. The webhook is unchanged: it is a side
// effect of creating a ticket, not part of storing it.
func NewPG(db *sql.DB, webhookURL string) (*PGStore, error) {
	if db == nil {
		return nil, errors.New("ticket: nil database handle")
	}
	return &PGStore{db: db, webhookURL: webhookURL, now: time.Now}, nil
}

func (p *PGStore) Persistent() bool { return p != nil && p.db != nil }
func (p *PGStore) Dispatches() bool { return p != nil && p.webhookURL != "" }

// Create opens a ticket, or returns the one already open for the path.
//
// Returning the existing ticket rather than an error is deliberate: the caller asked for
// this path to be owned by somebody, and it already is. Two engineers clicking the same
// button should converge on one ticket, not see a failure.
func (p *PGStore) Create(ctx context.Context, t Ticket) (Ticket, error) {
	if p == nil || p.db == nil {
		return Ticket{}, errors.New("ticket: store not configured")
	}
	if err := validate(t); err != nil {
		return Ticket{}, err
	}
	t.Tenant = tenantKey(t.Tenant)

	if existing, ok, err := p.OpenForPath(ctx, t.Tenant, t.PathID); err != nil {
		return Ticket{}, err
	} else if ok {
		return existing, nil
	}

	t.ID = "tk-" + randHex()
	t.Status = StatusOpen
	t.CreatedAt = p.now().UTC()
	t.ClosedAt = nil

	const q = `
		INSERT INTO tickets (id, tenant, path_id, title, route, owner, status, external_url, created_at, closed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL)`
	if _, err := p.db.ExecContext(ctx, q,
		t.ID, t.Tenant, t.PathID, t.Title, t.Route, t.Owner, string(t.Status), t.ExternalURL, t.CreatedAt); err != nil {
		return Ticket{}, fmt.Errorf("ticket: create for %s: %w", t.PathID, err)
	}

	dispatchTicket(ctx, p.webhookURL, t)
	return t, nil
}

// Close marks a ticket done. Closing one that is already closed is not an error - the
// end state is the same, and on several replicas another may have got there first.
func (p *PGStore) Close(ctx context.Context, tenant, id string) (Ticket, error) {
	if p == nil || p.db == nil {
		return Ticket{}, errors.New("ticket: store not configured")
	}
	const q = `
		UPDATE tickets SET status = $1, closed_at = COALESCE(closed_at, $2)
		WHERE tenant = $3 AND id = $4
		RETURNING id, tenant, path_id, title, route, owner, status, external_url, created_at, closed_at`
	t, err := scanTicket(p.db.QueryRowContext(ctx, q, string(StatusClosed), p.now().UTC(), tenantKey(tenant), id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Ticket{}, ErrNotFound
	case err != nil:
		return Ticket{}, fmt.Errorf("ticket: close %s: %w", id, err)
	}
	return t, nil
}

// List returns a tenant's tickets, newest first - closed ones included, because the work
// board shows what was done as well as what is outstanding.
func (p *PGStore) List(ctx context.Context, tenant string) ([]Ticket, error) {
	if p == nil || p.db == nil {
		return nil, errors.New("ticket: store not configured")
	}
	const q = `
		SELECT id, tenant, path_id, title, route, owner, status, external_url, created_at, closed_at
		FROM tickets WHERE tenant = $1 ORDER BY created_at DESC`
	rows, err := p.db.QueryContext(ctx, q, tenantKey(tenant))
	if err != nil {
		return nil, fmt.Errorf("ticket: list %s: %w", tenant, err)
	}
	defer func() { _ = rows.Close() }()

	var out []Ticket
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, fmt.Errorf("ticket: list %s: %w", tenant, err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// OpenForPath reports the open ticket for a path, if there is one. This is the check
// that stops a second ticket being opened for work somebody already owns.
func (p *PGStore) OpenForPath(ctx context.Context, tenant, pathID string) (Ticket, bool, error) {
	if p == nil || p.db == nil {
		return Ticket{}, false, errors.New("ticket: store not configured")
	}
	const q = `
		SELECT id, tenant, path_id, title, route, owner, status, external_url, created_at, closed_at
		FROM tickets
		WHERE tenant = $1 AND path_id = $2 AND status = 'open'
		ORDER BY created_at DESC LIMIT 1`
	t, err := scanTicket(p.db.QueryRowContext(ctx, q, tenantKey(tenant), pathID))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Ticket{}, false, nil
	case err != nil:
		return Ticket{}, false, fmt.Errorf("ticket: open ticket for %s: %w", pathID, err)
	}
	return t, true, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanTicket(row rowScanner) (Ticket, error) {
	var (
		t      Ticket
		status string
		closed sql.NullTime
	)
	if err := row.Scan(&t.ID, &t.Tenant, &t.PathID, &t.Title, &t.Route, &t.Owner,
		&status, &t.ExternalURL, &t.CreatedAt, &closed); err != nil {
		return Ticket{}, err
	}
	t.Status = Status(status)
	t.CreatedAt = t.CreatedAt.UTC()
	if closed.Valid {
		c := closed.Time.UTC()
		t.ClosedAt = &c
	}
	return t, nil
}
