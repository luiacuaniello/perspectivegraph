package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/lib/pq"
)

// PGStore keeps the temporal state in PostgreSQL, so every replica reads the same
// series.
//
// The problem it solves is the reads, not the writes. The analyzer is leader-gated, so
// only one process ever observes a pass - but a replica that is NOT the leader holds an
// empty in-memory history, and the trend chart is therefore full or blank depending on
// which pod answered the request. From here, every replica sees the same history.
//
// Writes stay best-effort, as they were: history is observability, and an analyzer pass
// must never fail because a trend point could not be recorded.
type PGStore struct {
	db          *sql.DB
	now         func() time.Time
	sampleEvery time.Duration
	maxPoints   int
}

// NewPG builds a Postgres-backed history store, taking the same coalescing window and
// retention as the file store so a deployment that switches backends sees the same
// shaped series rather than a suddenly denser or sparser chart.
func NewPG(db *sql.DB, sampleEvery time.Duration, maxPoints int) (*PGStore, error) {
	if db == nil {
		return nil, errors.New("history: nil database handle")
	}
	if sampleEvery <= 0 {
		sampleEvery = defaultSampleEvery
	}
	if maxPoints <= 0 {
		maxPoints = defaultMaxPoints
	}
	return &PGStore{db: db, now: time.Now, sampleEvery: sampleEvery, maxPoints: maxPoints}, nil
}

func (p *PGStore) Persistent() bool { return p != nil && p.db != nil }

// ObservePass records one analyzer pass: every open path is upserted, and anything that
// was open and is not in this pass is resolved.
//
// It runs in one transaction because a half-recorded pass is worse than an unrecorded
// one - a path marked resolved while its peers were not would contribute a bogus
// resolution to the MTTR, which is a number people plan work against.
func (p *PGStore) ObservePass(tenant string, open []Observation, riskPct float64) {
	if p == nil || p.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	now := p.now().UTC()
	tenant = tenantKey(tenant)

	if err := p.observe(ctx, tenant, open, now); err != nil {
		// Best-effort by design: observability must not fail an analyzer pass.
		slog.Warn("history: recording a pass failed", "tenant", tenant, "err", err)
		return
	}
	p.samplePosture(ctx, tenant, PosturePoint{At: now, CriticalPaths: len(open), RiskPct: riskPct})
}

func (p *PGStore) observe(ctx context.Context, tenant string, open []Observation, now time.Time) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	ids := make([]string, 0, len(open))
	for _, o := range open {
		ids = append(ids, o.ID)
		// A path that was resolved and is back is a REGRESSION, not a continuation:
		// first_seen restarts so "open for" reflects this occurrence rather than the
		// original one months ago, and the reopen is counted.
		const q = `
			INSERT INTO history_paths (tenant, id, route, score, first_seen, last_seen, open, resolved_at, reopens)
			VALUES ($1, $2, $3, $4, $5, $5, true, NULL, 0)
			ON CONFLICT (tenant, id) DO UPDATE SET
				route = EXCLUDED.route,
				score = EXCLUDED.score,
				last_seen = EXCLUDED.last_seen,
				open = true,
				resolved_at = NULL,
				first_seen = CASE WHEN history_paths.open THEN history_paths.first_seen ELSE EXCLUDED.first_seen END,
				reopens = history_paths.reopens + CASE WHEN history_paths.open THEN 0 ELSE 1 END`
		if _, err := tx.ExecContext(ctx, q, tenant, o.ID, o.Route, o.Score, now); err != nil {
			return fmt.Errorf("upsert path %s: %w", o.ID, err)
		}
	}

	// Anything open last pass and absent now is resolved, which is what feeds MTTR.
	const resolve = `
		UPDATE history_paths SET open = false, resolved_at = $2
		WHERE tenant = $1 AND open AND NOT (id = ANY($3))`
	if _, err := tx.ExecContext(ctx, resolve, tenant, now, pqStrings(ids)); err != nil {
		return fmt.Errorf("resolve closed paths: %w", err)
	}
	return tx.Commit()
}

// SampleTrend records a posture point without touching the path lifecycle, so the
// exposure line stays continuous across passes that change-detection skipped: a steady
// "12 paths for the last hour" is itself information.
func (p *PGStore) SampleTrend(tenant string, criticalPaths int, riskPct float64) {
	if p == nil || p.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	p.samplePosture(ctx, tenantKey(tenant),
		PosturePoint{At: p.now().UTC(), CriticalPaths: criticalPaths, RiskPct: riskPct})
}

// samplePosture appends a point, or refreshes the current one when it is still inside
// the sampling window.
//
// The window is anchored to the LAST point's timestamp rather than moved forward on each
// refresh. Sliding it would mean a busy tenant never appends at all, and the trend would
// be one perpetually-updated point instead of a line.
func (p *PGStore) samplePosture(ctx context.Context, tenant string, pt PosturePoint) {
	var lastAt time.Time
	err := p.db.QueryRowContext(ctx,
		`SELECT at FROM history_posture WHERE tenant = $1 ORDER BY at DESC LIMIT 1`, tenant).Scan(&lastAt)
	switch {
	case err == nil && pt.At.Sub(lastAt.UTC()) < p.sampleEvery:
		if _, uerr := p.db.ExecContext(ctx,
			`UPDATE history_posture SET critical_paths = $3, risk_pct = $4 WHERE tenant = $1 AND at = $2`,
			tenant, lastAt, pt.CriticalPaths, pt.RiskPct); uerr != nil {
			slog.Warn("history: coalescing a trend point failed", "err", uerr)
		}
		return
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		slog.Warn("history: reading the last trend point failed", "err", err)
		return
	}

	if _, err := p.db.ExecContext(ctx,
		`INSERT INTO history_posture (tenant, at, critical_paths, risk_pct) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant, at) DO UPDATE SET critical_paths = EXCLUDED.critical_paths, risk_pct = EXCLUDED.risk_pct`,
		tenant, pt.At, pt.CriticalPaths, pt.RiskPct); err != nil {
		slog.Warn("history: appending a trend point failed", "err", err)
		return
	}
	p.trim(ctx, tenant, seriesPosture)
}

// SampleCalibration records a point of the calibration trend, coalesced like the posture
// one so an operator can watch evidence accumulate without flooding the series.
func (p *PGStore) SampleCalibration(tenant string, brier, ece float64, samples int) {
	if p == nil || p.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	tenant = tenantKey(tenant)
	now := p.now().UTC()

	var lastAt time.Time
	err := p.db.QueryRowContext(ctx,
		`SELECT at FROM history_calibration WHERE tenant = $1 ORDER BY at DESC LIMIT 1`, tenant).Scan(&lastAt)
	if err == nil && now.Sub(lastAt.UTC()) < p.sampleEvery {
		if _, uerr := p.db.ExecContext(ctx,
			`UPDATE history_calibration SET brier = $3, ece = $4, samples = $5 WHERE tenant = $1 AND at = $2`,
			tenant, lastAt, brier, ece, samples); uerr != nil {
			slog.Warn("history: coalescing a calibration point failed", "err", uerr)
		}
		return
	}
	if _, err := p.db.ExecContext(ctx,
		`INSERT INTO history_calibration (tenant, at, brier, ece, samples) VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (tenant, at) DO NOTHING`, tenant, now, brier, ece, samples); err != nil {
		slog.Warn("history: appending a calibration point failed", "err", err)
		return
	}
	p.trim(ctx, tenant, seriesCalibration)
}

// series names a trimmable table.
//
// It is an enumerated type, and the queries below are whole literals, because the
// alternative - formatting the table name into the statement - builds SQL by string
// concatenation. Every caller today passes a constant, so it is safe today; that safety
// lives in a comment rather than in the compiler, and the first caller to pass a variable
// inherits an injection point in the one tool whose job is to find them. Written this way
// it cannot happen, and the security scanner has nothing to triage.
type series int

const (
	seriesPosture series = iota
	seriesCalibration
)

func (s series) String() string {
	if s == seriesPosture {
		return "history_posture"
	}
	return "history_calibration"
}

// trim keeps a series bounded, so a long-lived tenant's chart does not grow without end.
func (p *PGStore) trim(ctx context.Context, tenant string, s series) {
	const trimPosture = `
		DELETE FROM history_posture WHERE tenant = $1 AND at < (
			SELECT min(at) FROM (
				SELECT at FROM history_posture WHERE tenant = $1 ORDER BY at DESC LIMIT $2
			) keep
		)`
	const trimCalibration = `
		DELETE FROM history_calibration WHERE tenant = $1 AND at < (
			SELECT min(at) FROM (
				SELECT at FROM history_calibration WHERE tenant = $1 ORDER BY at DESC LIMIT $2
			) keep
		)`

	q := trimCalibration
	if s == seriesPosture {
		q = trimPosture
	}
	if _, err := p.db.ExecContext(ctx, q, tenant, p.maxPoints); err != nil {
		slog.Warn("history: trimming a series failed", "table", s.String(), "err", err)
	}
}

// Get returns one path's lifecycle record.
func (p *PGStore) Get(tenant, id string) (PathRecord, bool) {
	if p == nil || p.db == nil {
		return PathRecord{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()

	const q = `
		SELECT tenant, id, route, score, first_seen, last_seen, open, resolved_at, reopens
		FROM history_paths WHERE tenant = $1 AND id = $2`
	rec, err := scanPath(p.db.QueryRowContext(ctx, q, tenantKey(tenant), id))
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Warn("history: reading a path record failed", "id", id, "err", err)
		}
		return PathRecord{}, false
	}
	return rec, true
}

// Trend returns the most recent posture points, oldest first, capped at limit.
func (p *PGStore) Trend(tenant string, limit int) []PosturePoint {
	if p == nil || p.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	if limit <= 0 || limit > p.maxPoints {
		limit = p.maxPoints
	}

	const q = `
		SELECT at, critical_paths, risk_pct FROM (
			SELECT at, critical_paths, risk_pct FROM history_posture
			WHERE tenant = $1 ORDER BY at DESC LIMIT $2
		) recent ORDER BY at ASC`
	rows, err := p.db.QueryContext(ctx, q, tenantKey(tenant), limit)
	if err != nil {
		slog.Warn("history: reading the trend failed", "err", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []PosturePoint
	for rows.Next() {
		var pt PosturePoint
		if err := rows.Scan(&pt.At, &pt.CriticalPaths, &pt.RiskPct); err != nil {
			slog.Warn("history: reading the trend failed", "err", err)
			return nil
		}
		pt.At = pt.At.UTC()
		out = append(out, pt)
	}
	return out
}

// CalibrationTrend returns the most recent calibration points, oldest first.
func (p *PGStore) CalibrationTrend(tenant string, limit int) []CalibrationSample {
	if p == nil || p.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	if limit <= 0 || limit > p.maxPoints {
		limit = p.maxPoints
	}

	const q = `
		SELECT at, brier, ece, samples FROM (
			SELECT at, brier, ece, samples FROM history_calibration
			WHERE tenant = $1 ORDER BY at DESC LIMIT $2
		) recent ORDER BY at ASC`
	rows, err := p.db.QueryContext(ctx, q, tenantKey(tenant), limit)
	if err != nil {
		slog.Warn("history: reading the calibration trend failed", "err", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var out []CalibrationSample
	for rows.Next() {
		var cs CalibrationSample
		if err := rows.Scan(&cs.At, &cs.Brier, &cs.ECE, &cs.Samples); err != nil {
			slog.Warn("history: reading the calibration trend failed", "err", err)
			return nil
		}
		cs.At = cs.At.UTC()
		out = append(out, cs)
	}
	return out
}

// Stats aggregates the MTTR panel.
//
// The aggregate is computed in Go over the tenant's records rather than in SQL, so it
// runs the SAME arithmetic as the file store. An MTTR that shifted when a deployment
// changed backend would be indistinguishable from the team getting faster.
func (p *PGStore) Stats(tenant string) Stats {
	if p == nil || p.db == nil {
		return Stats{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()

	const q = `
		SELECT tenant, id, route, score, first_seen, last_seen, open, resolved_at, reopens
		FROM history_paths WHERE tenant = $1 ORDER BY id`
	rows, err := p.db.QueryContext(ctx, q, tenantKey(tenant))
	if err != nil {
		slog.Warn("history: reading stats failed", "err", err)
		return Stats{}
	}
	defer func() { _ = rows.Close() }()

	var recs []PathRecord
	for rows.Next() {
		rec, err := scanPath(rows)
		if err != nil {
			slog.Warn("history: reading stats failed", "err", err)
			return Stats{}
		}
		recs = append(recs, rec)
	}
	return statsOf(recs)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPath(row rowScanner) (PathRecord, error) {
	var (
		rec      PathRecord
		resolved sql.NullTime
	)
	if err := row.Scan(&rec.Tenant, &rec.ID, &rec.Route, &rec.Score,
		&rec.FirstSeen, &rec.LastSeen, &rec.Open, &resolved, &rec.Reopens); err != nil {
		return PathRecord{}, err
	}
	rec.FirstSeen = rec.FirstSeen.UTC()
	rec.LastSeen = rec.LastSeen.UTC()
	if resolved.Valid {
		r := resolved.Time.UTC()
		rec.ResolvedAt = &r
	}
	return rec, nil
}
