package pgmigrate

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// The migration runner is the thing that decides whether an upgrade is safe, so its
// tests are about the ways an upgrade goes wrong rather than the happy path: two
// replicas starting at once, a restart mid-loop, and a release rolled back onto a
// database a newer one has already migrated.
//
// Skipped without Postgres, like the AGE contract test.

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("PERSPECTIVE_TEST_MIGRATE_DSN")
	if dsn == "" {
		dsn = "postgres://pg:pg@localhost:5433/pgtest?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("no test database (%v)", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("no test database at %s (%v)", dsn, err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Each test starts from nothing - in a schema of its own.
	//
	// Two reasons it is a schema rather than a DROP TABLE list. It cannot rot: a migration
	// added later is covered without anyone remembering to extend a list, and because every
	// migration is CREATE TABLE IF NOT EXISTS, a table left behind by an earlier run would
	// make its migration a silent no-op - the fresh-database path these tests exist to
	// guard would be the one path never executed. And it does not reach outside itself: the
	// governance stores' own Postgres tests share this database and run in parallel with
	// this package, so dropping their tables here would fail their tests for a reason that
	// has nothing to do with what they assert.
	if _, err := db.Exec(`DROP SCHEMA IF EXISTS ` + testSchema + ` CASCADE`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := db.Exec(`CREATE SCHEMA ` + testSchema); err != nil {
		t.Fatalf("reset: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP SCHEMA IF EXISTS ` + testSchema + ` CASCADE`) })

	// A second pool whose search_path is that schema. Migrations then create their tables
	// inside it, and schema_migrations is this package's alone.
	scoped, err := sql.Open("postgres", withSearchPath(t, dsn))
	if err != nil {
		t.Fatalf("scoped pool: %v", err)
	}
	t.Cleanup(func() { _ = scoped.Close() })
	var got string
	if err := scoped.QueryRow(`SELECT current_schema()`).Scan(&got); err != nil {
		t.Fatalf("scoped pool: %v", err)
	}
	// Fail loudly rather than silently migrating the shared schema and wrecking the
	// other packages' tables.
	if got != testSchema {
		t.Fatalf("the scoped pool landed in schema %q, not %q - the search_path option was ignored", got, testSchema)
	}
	return scoped
}

// testSchema isolates this package's migrations from the governance stores that share the
// test database.
const testSchema = "pgmigrate_test"

// withSearchPath points a DSN at testSchema. Both DSN spellings lib/pq accepts are
// handled: a URL, and the key=value form somebody may set in the environment.
func withSearchPath(t *testing.T, dsn string) string {
	t.Helper()
	const opt = "-c search_path=" + testSchema
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		return dsn + " options='" + opt + "'"
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	q := u.Query()
	q.Set("options", opt)
	u.RawQuery = q.Encode()
	return u.String()
}

func TestApplyCreatesTheSchemaAndRecordsIt(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	n, err := Apply(ctx, db)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if n == 0 {
		t.Fatal("reported 0 migrations against an empty database")
	}

	var count int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("bookkeeping table: %v", err)
	}
	if count != n {
		t.Errorf("recorded %d versions after applying %d", count, n)
	}
	if _, err := db.Exec(`SELECT 1 FROM suppressions WHERE false`); err != nil {
		t.Errorf("the migration did not create suppressions: %v", err)
	}
}

// A restart must not re-run anything. This is the ordinary case - a pod restarts far more
// often than the schema changes - and re-running a CREATE would crash-loop it.
func TestApplyIsIdempotent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	first, err := Apply(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Apply(ctx, db)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if second != 0 {
		t.Errorf("re-applied %d migration(s) on an up-to-date database", second)
	}
	if first == 0 {
		t.Error("the first Apply did nothing")
	}
}

// A rolling update starts several replicas at once, and they all migrate. Without the
// advisory lock two would apply the same migration concurrently and the loser would fail
// on a duplicate object - crash-looping a deployment that was healthy a second earlier.
func TestConcurrentRunnersDoNotCollide(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	const replicas = 6
	var wg sync.WaitGroup
	errs := make([]error, replicas)
	counts := make([]int, replicas)
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			counts[i], errs[i] = Apply(ctx, db)
		}(i)
	}
	wg.Wait()

	total := 0
	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d failed to start: %v", i, err)
		}
		total += counts[i]
	}
	if t.Failed() {
		return
	}
	// Exactly one replica should have done the work; the rest find it done.
	if total == 0 {
		t.Fatal("no replica applied anything")
	}
	var applied int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if total != applied {
		t.Errorf("replicas applied %d migrations between them but %d are recorded - one ran twice",
			total, applied)
	}
}

// The rollback case, and the one that silently corrupts data if it is not caught: a
// release is deployed, migrates the schema, and is then rolled back. The older binary
// does not know that version. Running anyway means old code writing to a schema it does
// not understand, so it must refuse and say why.
func TestRefusesADatabaseMigratedByANewerRelease(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	if _, err := Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO schema_migrations (version, name) VALUES (9999, 'from-the-future')`); err != nil {
		t.Fatal(err)
	}
	// Remove it again: this row outlives the test, and anything else sharing this
	// database - the suppress package's Postgres tests do - would then refuse to
	// migrate, failing for a reason that has nothing to do with what it was testing.
	t.Cleanup(func() {
		if _, err := db.Exec(`DELETE FROM schema_migrations WHERE version = 9999`); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	_, err := Apply(ctx, db)
	if err == nil {
		t.Fatal("started against a database migrated by a newer release")
	}
	for _, want := range []string{"9999", "newer release"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so the operator cannot tell what happened: %v", want, err)
		}
	}
}

// The embedded set itself must be unambiguous: two files claiming one version would make
// "has it run?" a coin toss.
func TestEmbeddedMigrationsAreWellFormed(t *testing.T) {
	all, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("no migrations embedded")
	}
	seen := map[int]bool{}
	prev := 0
	for _, m := range all {
		if seen[m.version] {
			t.Errorf("version %d appears twice", m.version)
		}
		seen[m.version] = true
		if m.version <= prev {
			t.Errorf("version %d is out of order after %d", m.version, prev)
		}
		prev = m.version
		if strings.TrimSpace(m.body) == "" {
			t.Errorf("migration %d (%s) is empty", m.version, m.name)
		}
	}
}
