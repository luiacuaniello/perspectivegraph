package pgmigrate

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/luiacuaniello/perspectivegraph/internal/tenant"
)

// NormalizeTenants re-keys the governance tables to the tenant's one spelling
// (tenant.Normalize), and reports how many rows it moved.
//
// Rows written before a tenant had one spelling are keyed by the tenant as its token spelt
// it - "Acme-Corp" - while every write since keys "acme_corp", so without this they would
// no longer be found. It runs at every start, changes nothing once every tenant is in its
// normal form, and holds the migrations' advisory lock, so replicas starting together do it
// once. A path suppressed under two spellings of one tenant keeps the later decision.
//
// The history and the KEV holdout are not here: the analyzer has always written them under
// the normalized tenant. The audit log is not either: it records what was, and its chain
// covers the tenant as it was written.
func NormalizeTenants(ctx context.Context, db *sql.DB) (moved int64, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("normalize tenants: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return 0, fmt.Errorf("normalize tenants: take the advisory lock: %w", err)
	}

	for _, table := range []string{"suppressions", "tickets", "validations"} {
		spellings, err := tenantsIn(ctx, tx, table)
		if err != nil {
			return moved, err
		}
		for _, written := range spellings {
			normal := tenant.Normalize(written)
			if normal == written {
				continue
			}
			if table == "suppressions" {
				if err := keepTheLaterSuppression(ctx, tx, written, normal); err != nil {
					return moved, err
				}
			}
			// #nosec G202 -- table is one of the three constants above, never input
			res, err := tx.ExecContext(ctx, `UPDATE `+table+` SET tenant = $1 WHERE tenant = $2`, normal, written)
			if err != nil {
				return moved, fmt.Errorf("normalize tenants: %s %q: %w", table, written, err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return moved, err
			}
			moved += n
		}
	}
	if err := tx.Commit(); err != nil {
		return moved, fmt.Errorf("normalize tenants: %w", err)
	}
	return moved, nil
}

func tenantsIn(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	// #nosec G202 -- table is a constant of NormalizeTenants, never input
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT tenant FROM `+table)
	if err != nil {
		return nil, fmt.Errorf("normalize tenants: read %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// keepTheLaterSuppression clears the way for re-keying written to normal: wherever both
// spellings suppress one path, the earlier decision goes - the written one on a tie, the
// normal one being what every write since has used.
func keepTheLaterSuppression(ctx context.Context, tx *sql.Tx, written, normal string) error {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM suppressions s USING suppressions keep
		WHERE s.tenant = $1 AND keep.tenant = $2 AND keep.path_id = s.path_id
		  AND keep.created_at >= s.created_at`, written, normal); err != nil {
		return fmt.Errorf("normalize tenants: suppressions %q: %w", written, err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM suppressions s USING suppressions later
		WHERE s.tenant = $2 AND later.tenant = $1 AND later.path_id = s.path_id
		  AND later.created_at > s.created_at`, written, normal); err != nil {
		return fmt.Errorf("normalize tenants: suppressions %q: %w", normal, err)
	}
	return nil
}
