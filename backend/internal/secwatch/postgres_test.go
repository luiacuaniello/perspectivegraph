package secwatch

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/luiacuaniello/perspectivegraph/internal/pgmigrate"
)

func tripsDB(t *testing.T) *sql.DB {
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
	if _, err := pgmigrate.Apply(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM auth_lockout`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return db
}

// The finding this closes: the lockout lived only in memory, so a restart - or a deploy,
// which happens on a schedule anyone can read - handed a brute-forcer a clean slate.
func TestALockoutSurvivesARestart(t *testing.T) {
	db := tripsDB(t)
	ctx := context.Background()

	store, err := NewPGTrips(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	w := New(3, time.Minute, 15*time.Minute, nil).WithTripStore(store)
	for i := 0; i < 3; i++ {
		w.Observe("198.51.100.7", 1)
	}
	if !w.Tripped("198.51.100.7") {
		t.Fatal("the threshold was crossed but the key is not locked")
	}

	// A new process over the same database: nothing in memory, everything to learn.
	restarted, err := NewPGTrips(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	fresh := New(3, time.Minute, 15*time.Minute, nil).WithTripStore(restarted)
	if !fresh.Tripped("198.51.100.7") {
		t.Error("the lockout did not survive the restart - waiting for a deploy still clears it")
	}
	if fresh.Tripped("203.0.113.9") {
		t.Error("an unrelated address was reported as locked")
	}
}

// A second replica must enforce a lockout the first one set, or the client simply
// retries until it lands on a pod that has never heard of it.
func TestAnotherReplicaSeesTheLockout(t *testing.T) {
	db := tripsDB(t)
	ctx := context.Background()

	a, err := NewPGTrips(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	New(2, time.Minute, 15*time.Minute, nil).WithTripStore(a).Observe("198.51.100.7", 2)

	b, err := NewPGTrips(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if !New(2, time.Minute, 15*time.Minute, nil).WithTripStore(b).Tripped("198.51.100.7") {
		t.Error("a second replica did not enforce the lockout")
	}
}

// A lockout is a pause, not a ban: it must expire on its own, and the row must go with
// it rather than accumulating one per lockout ever taken.
func TestAnExpiredLockoutStopsLockingAndIsSweptAway(t *testing.T) {
	db := tripsDB(t)
	ctx := context.Background()

	store, err := NewPGTrips(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	store.Trip("198.51.100.7", time.Now().Add(-time.Minute)) // already over

	if store.Locked("198.51.100.7") {
		t.Error("an expired lockout still locks")
	}
	// Force the sweep the refresh performs, then check the row is gone.
	if err := store.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM auth_lockout WHERE key = '198.51.100.7'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("the expired row was not swept: %d left", n)
	}
}

// Without a store the watcher must behave exactly as it always has - the demo profile
// has no database, and this change must not make it depend on one.
func TestWithoutAStoreNothingChanges(t *testing.T) {
	w := New(2, time.Minute, 15*time.Minute, nil)
	if w.Tripped("198.51.100.7") {
		t.Fatal("locked before anything happened")
	}
	w.Observe("198.51.100.7", 2)
	if !w.Tripped("198.51.100.7") {
		t.Error("the in-memory lockout stopped working")
	}
}
