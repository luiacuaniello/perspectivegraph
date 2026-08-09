// Package pgmigrate applies ordered, versioned schema changes to PostgreSQL.
//
// It is hand-rolled rather than a dependency, and small enough to read in one sitting.
// The project takes its dependency count seriously, and what a migration runner has to
// get right is not volume of code but four specific behaviours:
//
//   - ONE writer. Several replicas start at once during a rolling update, so the runner
//     takes a session-scoped advisory lock first. Without it two replicas apply the same
//     migration concurrently and the second fails on a duplicate object, crash-looping a
//     deployment that was healthy a moment ago.
//   - ONE transaction per migration. A half-applied schema change is worse than a failed
//     one, because the next start sees a version that was never recorded and re-runs it.
//   - FAIL CLOSED on a newer database. If the database has a version this binary has
//     never heard of, someone rolled a release back. Running anyway means old code
//     writing to a schema it does not understand - so it refuses and says so.
//   - IDEMPOTENT. Applying twice is a no-op, because a restart loop must not corrupt
//     anything.
package pgmigrate

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strconv"
	"strings"
)

// migrationsFS holds the ordered schema changes. A file is named "<version>_<name>.sql",
// version being a positive integer with no gaps required - only ordering.
//
//go:embed sql/*.sql
var migrationsFS embed.FS

// lockKey is the advisory-lock id this runner serialises on. It is arbitrary but must
// not collide with the leader election's, which derives its own from a different string.
const lockKey int64 = 8_040_192_255_101

type migration struct {
	version int
	name    string
	body    string
}

// Apply brings the database up to the schema this binary expects.
//
// It reports how many migrations it ran, so a caller can log "already up to date"
// distinctly from "applied 3" - the difference matters when diagnosing a deployment that
// came up against the wrong database.
func Apply(ctx context.Context, db *sql.DB) (applied int, err error) {
	all, err := load()
	if err != nil {
		return 0, err
	}

	// One connection for the whole run: an advisory lock is tied to the session that
	// took it, so it has to be released on that same connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, fmt.Errorf("migrate: connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		return 0, fmt.Errorf("migrate: acquire lock: %w", err)
	}
	defer func() {
		if _, uerr := conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockKey); uerr != nil {
			slog.Warn("migrate: releasing the advisory lock failed", "err", uerr)
		}
	}()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    integer PRIMARY KEY,
			name       text        NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("migrate: create bookkeeping table: %w", err)
	}

	done, err := appliedVersions(ctx, conn)
	if err != nil {
		return 0, err
	}

	// A version in the database that this binary does not carry means the database is
	// AHEAD: someone deployed a newer release and then rolled back. Old code against a
	// newer schema writes data the new code will misread, so refuse.
	known := map[int]bool{}
	for _, m := range all {
		known[m.version] = true
	}
	for v := range done {
		if !known[v] {
			return 0, fmt.Errorf(
				"migrate: the database is at schema version %d, which this build does not know - "+
					"it was migrated by a newer release. Deploy that release again, or restore a backup "+
					"taken before it", v)
		}
	}

	for _, m := range all {
		if done[m.version] {
			continue
		}
		if err := applyOne(ctx, conn, m); err != nil {
			return applied, err
		}
		slog.Info("migrate: applied", "version", m.version, "name", m.name)
		applied++
	}
	return applied, nil
}

// applyOne runs one migration and records it in the SAME transaction, so the schema and
// the bookkeeping can never disagree.
func applyOne(ctx context.Context, conn *sql.Conn, m migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate %d: begin: %w", m.version, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.body); err != nil {
		return fmt.Errorf("migrate %d (%s): %w", m.version, m.name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
		return fmt.Errorf("migrate %d: record: %w", m.version, err)
	}
	return tx.Commit()
}

func appliedVersions(ctx context.Context, conn *sql.Conn) (map[int]bool, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrate: read applied versions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	done := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		done[v] = true
	}
	return done, rows.Err()
}

// load reads the embedded migrations in version order, refusing anything ambiguous: a
// duplicate version or an unparseable name would make "which ran already" a guess.
func load() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "sql")
	if err != nil {
		return nil, err
	}

	var out []migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		num, name, ok := strings.Cut(strings.TrimSuffix(e.Name(), ".sql"), "_")
		if !ok {
			return nil, fmt.Errorf("migrate: %q is not named <version>_<name>.sql", e.Name())
		}
		v, err := strconv.Atoi(num)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("migrate: %q has no positive integer version", e.Name())
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("migrate: version %d is used by both %q and %q", v, prev, e.Name())
		}
		seen[v] = e.Name()

		body, err := migrationsFS.ReadFile("sql/" + e.Name())
		if err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(string(body))) == 0 {
			return nil, fmt.Errorf("migrate: %q is empty", e.Name())
		}
		out = append(out, migration{version: v, name: name, body: string(body)})
	}
	if len(out) == 0 {
		return nil, errors.New("migrate: no migrations embedded")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}
