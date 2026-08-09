package suppress

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/luiacuaniello/perspectivegraph/internal/pgmigrate"
)

// The Postgres backend is what removes the single-replica ceiling, so its tests are
// about the properties the file store could not offer: two writers seeing each other,
// tenants that cannot read across, and expiry decided by the database rather than by
// whichever replica happened to ask.
//
// Skipped without Postgres, like the AGE contract test.

func pgStore(t *testing.T) *PGStore {
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
	if _, err := db.Exec(`DELETE FROM suppressions`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := NewPG(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rec(tenant, path string) Record {
	return Record{Tenant: tenant, PathID: path, Reason: ReasonAcceptRisk, Owner: "sec-team"}
}

// The property the file store could not have: a decision made by one replica is visible
// to another. Two stores over the same database stand in for two pods.
func TestASuppressionByOneReplicaIsVisibleToAnother(t *testing.T) {
	a := pgStore(t)
	b, err := NewPG(a.db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := a.Put(ctx, rec("acme", "ap-1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := b.Get(ctx, "acme", "ap-1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the second replica cannot see the suppression - the board would show the path to half the users")
	}
	if got.Owner != "sec-team" {
		t.Errorf("owner = %q", got.Owner)
	}
}

// Re-suppressing an already-suppressed path is the ordinary case - an analyst changing
// the reason or extending the expiry - and must not fail on the primary key.
func TestPutReplacesRatherThanConflicting(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	if _, err := s.Put(ctx, rec("acme", "ap-1")); err != nil {
		t.Fatal(err)
	}
	second := rec("acme", "ap-1")
	second.Reason = ReasonFalsePositive
	second.Note = "not reachable from the internet after all"
	if _, err := s.Put(ctx, second); err != nil {
		t.Fatalf("re-suppressing failed: %v", err)
	}

	got, ok, err := s.Get(ctx, "acme", "ap-1")
	if err != nil || !ok {
		t.Fatalf("Get: %v ok=%v", err, ok)
	}
	if got.Reason != ReasonFalsePositive || got.Note == "" {
		t.Errorf("the second decision did not replace the first: %+v", got)
	}
	all, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Errorf("%d rows for one path", len(all))
	}
}

// The tenant is in the primary key, so isolation is the database's job. One tenant must
// never read another's decisions.
func TestTenantsCannotSeeEachOther(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	if _, err := s.Put(ctx, rec("acme", "ap-shared")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, rec("globex", "ap-shared")); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, "acme", "ap-shared"); !ok {
		t.Error("acme lost its own suppression")
	}
	list, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list {
		if r.Tenant != "acme" {
			t.Errorf("acme's list contains a %s row", r.Tenant)
		}
	}
	if len(list) != 1 {
		t.Errorf("acme sees %d rows, want 1", len(list))
	}
}

// Expiry is evaluated by the database, so replicas whose clocks disagree still agree on
// what has lapsed. An expired suppression reads as absent - the path is live again - but
// stays in the list, because the board shows lapsed decisions.
func TestExpiryIsDecidedByTheDatabase(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	expired := rec("acme", "ap-expired")
	expired.ExpiresAt = &past
	if _, err := s.Put(ctx, expired); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	live := rec("acme", "ap-live")
	live.ExpiresAt = &future
	if _, err := s.Put(ctx, live); err != nil {
		t.Fatal(err)
	}

	if _, ok, _ := s.Get(ctx, "acme", "ap-expired"); ok {
		t.Error("an expired suppression still hides its path")
	}
	if _, ok, _ := s.Get(ctx, "acme", "ap-live"); !ok {
		t.Error("a live suppression was treated as lapsed")
	}

	active, err := s.ActiveSet(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, in := active["ap-expired"]; in {
		t.Error("the active set includes an expired suppression")
	}
	if _, in := active["ap-live"]; !in {
		t.Error("the active set is missing a live suppression")
	}

	all, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("List returned %d, want both - lapsed decisions stay visible on the board", len(all))
	}
}

// Validation is shared with the file backend, so a record Postgres accepts could not
// have been refused by the other. Rules that drift between backends are how a
// deployment's data stops meaning the same thing when it migrates.
func TestValidationMatchesTheFileBackend(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()

	for name, r := range map[string]Record{
		"no path id": {Tenant: "acme", Owner: "sec", Reason: ReasonAcceptRisk},
		"no owner":   {Tenant: "acme", PathID: "p", Reason: ReasonAcceptRisk},
		"bad reason": {Tenant: "acme", PathID: "p", Owner: "sec", Reason: Reason("because-i-said-so")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Put(ctx, r); err == nil {
				t.Error("accepted an unaccountable suppression")
			}
		})
	}
}

// Deleting something that is not there is not an error: on several replicas the other
// one may simply have got there first, and the desired end state is reached either way.
func TestDeleteIsIdempotent(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	if err := s.Delete(ctx, "acme", "never-existed"); err != nil {
		t.Errorf("deleting an absent suppression failed: %v", err)
	}
}
