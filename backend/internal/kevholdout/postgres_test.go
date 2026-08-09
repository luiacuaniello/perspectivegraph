package kevholdout

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/luiacuaniello/perspectivegraph/internal/pgmigrate"
)

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
	if _, err := db.Exec(`DELETE FROM kev_holdout`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := NewPGStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func snap(tenant, cve string, at time.Time) Snapshot {
	return Snapshot{CVE: cve, Predicted: 0.4, EPSS: 0.12, Basis: "epss", SealedAt: at, Tenant: tenant}
}

// The property the whole holdout rests on: a seal is made ONCE, and re-sealing must not
// move its grading date. If it did, a restart would push the window forward every time
// and the forecast would never come due - the holdout would quietly measure nothing
// while looking like it was working.
func TestResealingDoesNotMoveTheGradingDate(t *testing.T) {
	s := pgStore(t)
	original := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)

	if !s.seal(snap("acme", "CVE-2021-44228", original)) {
		t.Fatal("the first seal was rejected")
	}
	if s.seal(snap("acme", "CVE-2021-44228", time.Now())) {
		t.Error("a second seal was accepted, which would restart the window")
	}

	pending := s.Pending()
	if len(pending) != 1 {
		t.Fatalf("%d pending forecasts, want 1", len(pending))
	}
	if !pending[0].SealedAt.Equal(original) {
		t.Errorf("sealed_at moved from %s to %s - the forecast would never come due",
			original, pending[0].SealedAt)
	}
}

// A sealed forecast must survive the process that made it - that is the difference
// between evidence and a story told afterwards.
func TestSealsSurviveAcrossProcesses(t *testing.T) {
	first := pgStore(t)
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	first.seal(snap("acme", "CVE-2022-22965", at))

	second, err := NewPGStore(first.db)
	if err != nil {
		t.Fatal(err)
	}
	pending := second.Pending()
	if len(pending) != 1 || pending[0].CVE != "CVE-2022-22965" {
		t.Fatalf("a new process sees %d pending forecasts: %+v", len(pending), pending)
	}
	if pending[0].Predicted != 0.4 || pending[0].Basis != "epss" {
		t.Errorf("the sealed evidence changed in transit: %+v", pending[0])
	}
}

// Once graded, a forecast is dropped so it is not graded twice.
func TestDropRemovesAGradedForecast(t *testing.T) {
	s := pgStore(t)
	s.seal(snap("acme", "CVE-2023-1", time.Now()))
	s.drop("acme", "CVE-2023-1")
	if got := len(s.Pending()); got != 0 {
		t.Errorf("%d forecasts still pending after grading", got)
	}
}

// The same CVE sealed for two tenants is two forecasts: each estate's prediction is its
// own, and grading one must not remove the other's.
func TestTheSameCVEForTwoTenantsIsTwoForecasts(t *testing.T) {
	s := pgStore(t)
	at := time.Now().UTC()
	s.seal(snap("acme", "CVE-2024-1", at))
	s.seal(snap("globex", "CVE-2024-1", at))

	if got := len(s.Pending()); got != 2 {
		t.Fatalf("%d pending, want one per tenant", got)
	}
	s.drop("acme", "CVE-2024-1")
	pending := s.Pending()
	if len(pending) != 1 || pending[0].Tenant != "globex" {
		t.Errorf("grading acme's forecast disturbed globex's: %+v", pending)
	}
}
