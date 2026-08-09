package validation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// PGStore keeps red-team and BAS verdicts in PostgreSQL.
//
// These are the records every calibration number is computed from, which is why this one
// matters more than the others. On the file backend they live in an append-only log that
// one process owns and periodically compacts; a second replica writing the same file
// would interleave events into it and the compaction would then resolve them in an order
// neither process chose. What comes out is not a corrupted file - it is a plausible one
// with the wrong evidence in it, and every Brier score and reliability diagram computed
// afterwards is quietly wrong with nothing to indicate it.
//
// The calibration arithmetic itself is NOT reimplemented here. Metrics and Calibration
// read the records and hand them to the same functions the file backend uses, so a
// deployment that changes backend cannot see its accuracy numbers move.
type PGStore struct {
	db    *sql.DB
	now   func() time.Time
	newID func() string
}

// NewPG builds a Postgres-backed verdict store.
func NewPG(db *sql.DB) (*PGStore, error) {
	if db == nil {
		return nil, errors.New("validation: nil database handle")
	}
	return &PGStore{db: db, now: time.Now, newID: newRecordID}, nil
}

func (p *PGStore) Persistent() bool { return p != nil && p.db != nil }

// Put records a verdict. Evidence is append-only in spirit: a verdict is an observation
// somebody made at a point in time, so re-recording the same id replaces it rather than
// creating a second copy of the same test.
func (p *PGStore) Put(ctx context.Context, r Record) (Record, error) {
	if p == nil || p.db == nil {
		return Record{}, errors.New("validation: store not configured")
	}
	r, err := normalize(r, p.now, p.newID)
	if err != nil {
		return Record{}, err
	}

	const q = `
		INSERT INTO validations (tenant, id, path_id, outcome, source, evidence, route, tested_at,
			predicted_score, scope, predicted_compromise, hops, correlated_hops, weight_basis, detected)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (tenant, id) DO UPDATE SET
			path_id = EXCLUDED.path_id, outcome = EXCLUDED.outcome, source = EXCLUDED.source,
			evidence = EXCLUDED.evidence, route = EXCLUDED.route, tested_at = EXCLUDED.tested_at,
			predicted_score = EXCLUDED.predicted_score, scope = EXCLUDED.scope,
			predicted_compromise = EXCLUDED.predicted_compromise, hops = EXCLUDED.hops,
			correlated_hops = EXCLUDED.correlated_hops, weight_basis = EXCLUDED.weight_basis,
			detected = EXCLUDED.detected`
	if _, err := p.db.ExecContext(ctx, q,
		r.Tenant, r.ID, r.PathID, string(r.Outcome), r.Source, r.Evidence, r.Route, r.TestedAt,
		r.PredictedScore, string(r.Scope), r.PredictedCompromise, r.Hops, r.CorrelatedHops,
		r.WeightBasis, detectedArg(r.Detected)); err != nil {
		return Record{}, fmt.Errorf("validation: put %s: %w", r.ID, err)
	}
	return r, nil
}

// Delete removes a verdict. Deleting evidence is a real act - it changes what the
// calibration is computed from - so an absent record is reported rather than shrugged
// off: the caller asked to remove something and should know it was not there.
func (p *PGStore) Delete(ctx context.Context, tenant, id string) error {
	if p == nil || p.db == nil {
		return errors.New("validation: store not configured")
	}
	res, err := p.db.ExecContext(ctx,
		`DELETE FROM validations WHERE tenant = $1 AND id = $2`, tenantKey(tenant), id)
	if err != nil {
		return fmt.Errorf("validation: delete %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// Get returns the most recent verdict recorded for a path.
func (p *PGStore) Get(ctx context.Context, tenant, pathID string) (Record, bool, error) {
	if p == nil || p.db == nil {
		return Record{}, false, errors.New("validation: store not configured")
	}
	const q = selectCols + `
		FROM validations WHERE tenant = $1 AND path_id = $2 ORDER BY tested_at DESC LIMIT 1`
	r, err := scanRecord(p.db.QueryRowContext(ctx, q, tenantKey(tenant), pathID))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Record{}, false, nil
	case err != nil:
		return Record{}, false, fmt.Errorf("validation: get %s: %w", pathID, err)
	}
	return r, true, nil
}

// List returns a tenant's verdicts, newest first.
func (p *PGStore) List(ctx context.Context, tenant string) ([]Record, error) {
	if p == nil || p.db == nil {
		return nil, errors.New("validation: store not configured")
	}
	return p.records(ctx, tenant)
}

// Metrics reports precision/recall over the recorded verdicts.
func (p *PGStore) Metrics(ctx context.Context, tenant string) (Metrics, error) {
	recs, err := p.records(ctx, tenant)
	if err != nil {
		return Metrics{}, err
	}
	return metricsOf(recs), nil
}

// Calibration reports the reliability of the engine's own scores.
//
// The arithmetic is the file backend's, run over the rows read here. Reimplementing it
// would let two deployments disagree about how well the engine is calibrated purely
// because of where they store their evidence.
func (p *PGStore) Calibration(ctx context.Context, tenant string) (Calibration, error) {
	recs, err := p.records(ctx, tenant)
	if err != nil {
		return Calibration{Bins: emptyBins(), Verdict: "insufficient-data"}, err
	}
	return calibrationOf(recs, true), nil
}

func (p *PGStore) records(ctx context.Context, tenant string) ([]Record, error) {
	const q = selectCols + ` FROM validations WHERE tenant = $1 ORDER BY tested_at DESC`
	rows, err := p.db.QueryContext(ctx, q, tenantKey(tenant))
	if err != nil {
		return nil, fmt.Errorf("validation: read %s: %w", tenant, err)
	}
	defer func() { _ = rows.Close() }()

	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("validation: read %s: %w", tenant, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const selectCols = `
	SELECT tenant, id, path_id, outcome, source, evidence, route, tested_at,
	       predicted_score, scope, predicted_compromise, hops, correlated_hops,
	       weight_basis, detected`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(row rowScanner) (Record, error) {
	var (
		r        Record
		outcome  string
		scope    string
		detected sql.NullBool
	)
	if err := row.Scan(&r.Tenant, &r.ID, &r.PathID, &outcome, &r.Source, &r.Evidence, &r.Route,
		&r.TestedAt, &r.PredictedScore, &scope, &r.PredictedCompromise, &r.Hops,
		&r.CorrelatedHops, &r.WeightBasis, &detected); err != nil {
		return Record{}, err
	}
	r.Outcome = Outcome(outcome)
	r.Scope = Scope(scope)
	r.TestedAt = r.TestedAt.UTC()
	// NULL stays nil: "not recorded" and "recorded as not detected" are different
	// claims, and the detection diagnostics distinguish them.
	if detected.Valid {
		d := detected.Bool
		r.Detected = &d
	}
	return r, nil
}

func detectedArg(d *bool) any {
	if d == nil {
		return nil
	}
	return *d
}
