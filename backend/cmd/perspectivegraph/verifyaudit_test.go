package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/pgmigrate"
)

// testSchema keeps this package's audit tables out of everyone else's way. The governance
// stores' own Postgres tests share this database and `go test ./...` runs the packages in
// parallel, so the tables below must not be the ones they are reading - one test here
// renames audit_log to prove a missing chain is not reported as tampering, and in the
// shared schema that briefly made the table vanish underneath another package's test.
const testSchema = "verifyaudit_test"

// govDB is the governance database the Postgres-backed tests need. Same env var and same
// skip as internal/audit's own suite, so these run in the AGE-integration CI job and stay
// out of the way of a laptop with no database. It returns a DSN scoped to testSchema,
// which is what the subcommand under test reads through POSTGRES_DSN.
func govDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("PERSPECTIVE_TEST_MIGRATE_DSN")
	if dsn == "" {
		dsn = "postgres://pg:pg@localhost:5433/pgtest?sslmode=disable"
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("no test database (%v)", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		_ = admin.Close()
		t.Skipf("no test database at %s (%v)", dsn, err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	// Each test starts from an empty schema of its own, so nothing leaks between tests
	// here either - including the retention checkpoint, which declares where the chain
	// starts and would make a fresh chain look truncated.
	if _, err := admin.Exec(`DROP SCHEMA IF EXISTS ` + testSchema + ` CASCADE`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA ` + testSchema); err != nil {
		t.Fatalf("reset: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + testSchema + ` CASCADE`) })

	scoped := withSearchPath(t, dsn)
	db, err := sql.Open("postgres", scoped)
	if err != nil {
		t.Fatalf("scoped pool: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var current string
	if err := db.QueryRow(`SELECT current_schema()`).Scan(&current); err != nil {
		t.Fatalf("scoped pool: %v", err)
	}
	if current != testSchema {
		t.Fatalf("scoped pool landed in schema %q - it would migrate the shared one", current)
	}
	if _, err := pgmigrate.Apply(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db, scoped
}

// withSearchPath returns dsn with the connection pinned to testSchema, in whichever of the
// two DSN forms the caller used.
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

// recordPG appends n records and drains the queue. PGLog appends asynchronously, so a
// test that verified without closing would read a chain still being written and fail on
// timing rather than on behaviour.
func recordPG(t *testing.T, db *sql.DB, n int) {
	t.Helper()
	log, err := audit.OpenPG(db)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		log.Record(context.Background(), "view.attack_paths", "token:abc123", "viewer", "acme", map[string]any{"n": i})
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// The whole point of the subcommand: under GOVERNANCE_BACKEND=postgres the chain is in
// the database, and until this existed the documented verification could not reach it.
func TestVerifyAuditReadsThePostgresChain(t *testing.T) {
	db, dsn := govDB(t)
	recordPG(t, db, 3)
	t.Setenv("POSTGRES_DSN", dsn)
	t.Setenv("STORE_ENCRYPTION_KEY", "")

	var out bytes.Buffer
	if err := runVerifyAudit([]string{"-postgres"}, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "audit chain OK: 3 records verified") {
		t.Errorf("got %q, want the 3-record OK line", got)
	}
}

// A verifier that reports OK on a mutilated chain is worse than none, so this asserts the
// command actually reaches VerifyPG rather than merely returning nil.
func TestVerifyAuditReportsPostgresTampering(t *testing.T) {
	db, dsn := govDB(t)
	recordPG(t, db, 4)
	t.Setenv("POSTGRES_DSN", dsn)
	t.Setenv("STORE_ENCRYPTION_KEY", "")

	// Delete a record in the middle: the one after it now points at a hash that is no
	// longer there, which is exactly what a chain exists to make visible.
	if _, err := db.Exec(`DELETE FROM audit_log WHERE seq = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	var out bytes.Buffer
	err := runVerifyAudit([]string{"-postgres"}, &out)
	if err == nil {
		t.Fatal("a chain with a deleted record verified clean")
	}
	if !strings.Contains(err.Error(), "audit chain INVALID") {
		t.Errorf("got %q, want it to name the chain as invalid", err)
	}
	if out.Len() != 0 {
		t.Errorf("printed %q on a tampered chain - nothing may look like success", out.String())
	}
}

// Pointing at a database the backend never ran against must not read as tampering: a
// mistyped DSN and a forged audit log are opposite problems.
func TestVerifyAuditSeparatesAMissingChainFromATamperedOne(t *testing.T) {
	db, dsn := govDB(t)
	if _, err := db.Exec(`ALTER TABLE audit_log RENAME TO audit_log_hidden`); err != nil {
		t.Fatalf("hide table: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`ALTER TABLE audit_log_hidden RENAME TO audit_log`) })
	t.Setenv("POSTGRES_DSN", dsn)

	err := runVerifyAudit([]string{"-postgres"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("a database with no audit chain verified clean")
	}
	if strings.Contains(err.Error(), "INVALID") {
		t.Errorf("got %q - a missing chain must not be reported as tampering", err)
	}
	if !strings.Contains(err.Error(), "audit_log") {
		t.Errorf("got %q, want it to name the missing table", err)
	}
}

// The file path is the one operators already use; it must keep working unchanged.
func TestVerifyAuditStillReadsAFileChain(t *testing.T) {
	t.Setenv("STORE_ENCRYPTION_KEY", "")
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	log.Record(context.Background(), "view.graph", "token:abc123", "viewer", "acme", nil)
	log.Record(context.Background(), "export.oscal", "token:abc123", "admin", "acme", nil)
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runVerifyAudit([]string{path}, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "audit chain OK: 2 records verified") {
		t.Errorf("got %q, want the 2-record OK line", got)
	}
}

// `verify-audit` with nothing after it used to fall through the dispatch and start the
// server. It must now say what it wanted instead.
func TestVerifyAuditWithNoTargetAsksForOne(t *testing.T) {
	err := runVerifyAudit(nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("no target was accepted")
	}
	if !strings.Contains(err.Error(), "-postgres") {
		t.Errorf("got %q, want it to name both ways to point the command at a chain", err)
	}
}
