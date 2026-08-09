package kevholdout

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	_ "github.com/lib/pq"
)

// PGStore keeps sealed forecasts in PostgreSQL.
//
// The holdout's whole claim rests on the seal surviving: a prediction is recorded BEFORE
// the outcome is known and graded only once its window has passed, which is what makes
// the result evidence rather than a story told afterwards. A forecast that disappeared
// with a pod, or that two replicas sealed at different moments, would be graded against
// a window nobody chose - and the grade would look exactly as legitimate as a real one.
type PGStore struct {
	db *sql.DB
}

// NewPGStore builds a Postgres-backed holdout store.
func NewPGStore(db *sql.DB) (*PGStore, error) {
	if db == nil {
		return nil, errors.New("kevholdout: nil database handle")
	}
	return &PGStore{db: db}, nil
}

// Pending returns every sealed forecast still awaiting its grading date.
func (p *PGStore) Pending() []Snapshot {
	if p == nil || p.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := p.db.QueryContext(ctx,
		`SELECT cve, predicted, epss, basis, sealed_at, tenant FROM kev_holdout ORDER BY sealed_at`)
	if err != nil {
		slog.Warn("kev holdout: reading pending forecasts failed", "err", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []Snapshot
	for rows.Next() {
		var s Snapshot
		if err := rows.Scan(&s.CVE, &s.Predicted, &s.EPSS, &s.Basis, &s.SealedAt, &s.Tenant); err != nil {
			slog.Warn("kev holdout: reading pending forecasts failed", "err", err)
			return nil
		}
		s.SealedAt = s.SealedAt.UTC()
		out = append(out, s)
	}
	return out
}

// seal records a forecast, and reports whether it was new.
//
// An existing seal is NEVER overwritten. Re-sealing would move the grading date forward
// every time the process restarted, so a forecast would never come due and the holdout
// would quietly measure nothing.
func (p *PGStore) seal(snap Snapshot) bool {
	if p == nil || p.db == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := p.db.ExecContext(ctx, `
		INSERT INTO kev_holdout (tenant, cve, predicted, epss, basis, sealed_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant, cve) DO NOTHING`,
		snap.Tenant, snap.CVE, snap.Predicted, snap.EPSS, snap.Basis, snap.SealedAt.UTC())
	if err != nil {
		slog.Warn("kev holdout: sealing a forecast failed", "cve", snap.CVE, "err", err)
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n > 0
}

// drop removes a forecast once it has been graded.
func (p *PGStore) drop(tenant, cve string) {
	if p == nil || p.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.db.ExecContext(ctx,
		`DELETE FROM kev_holdout WHERE tenant = $1 AND cve = $2`, tenant, cve); err != nil {
		slog.Warn("kev holdout: dropping a graded forecast failed", "cve", cve, "err", err)
	}
}

// flush is a no-op: every write above is already durable.
func (p *PGStore) flush() error { return nil }
