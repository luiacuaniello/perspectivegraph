package validation

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
	if _, err := db.Exec(`DELETE FROM validations`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	s, err := NewPG(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verdict(tenant, pathID string, o Outcome) Record {
	return Record{Tenant: tenant, PathID: pathID, Outcome: o, Source: "bas-tool"}
}

// THE reason this store had to move, and why it matters more than the others. On the
// file backend these live in an append-only log one process owns and periodically
// compacts. A second replica writing that file interleaves events into it, and the
// compaction then resolves them in an order neither process chose. What comes out is not
// a corrupted file - it is a plausible one with the wrong evidence in it, and every
// calibration number computed afterwards is quietly wrong.
func TestVerdictsFromTwoReplicasBothSurvive(t *testing.T) {
	a := pgStore(t)
	b, err := NewPG(a.db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := a.Put(ctx, verdict("acme", "ap-1", Confirmed)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Put(ctx, verdict("acme", "ap-2", Refuted)); err != nil {
		t.Fatal(err)
	}

	for name, s := range map[string]*PGStore{"replica A": a, "replica B": b} {
		list, err := s.List(ctx, "acme")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(list) != 2 {
			t.Errorf("%s sees %d verdicts, want both - evidence recorded elsewhere is missing", name, len(list))
		}
	}
}

// Precision and recall must come out of the database exactly as the file backend
// computes them. A precision that moved when a deployment changed where it stores its
// evidence would be indistinguishable from the engine getting better.
func TestMetricsMatchTheFileBackend(t *testing.T) {
	ctx := context.Background()
	pg := pgStore(t)
	file, err := New("")
	if err != nil {
		t.Fatal(err)
	}

	recs := []Record{
		verdict("acme", "ap-1", Confirmed),
		verdict("acme", "ap-2", Confirmed),
		verdict("acme", "ap-3", Refuted),
		{Tenant: "acme", Outcome: Missed, Source: "tester", Route: "lb -> db"},
	}
	for _, r := range recs {
		if _, err := pg.Put(ctx, r); err != nil {
			t.Fatalf("pg put: %v", err)
		}
		if _, err := file.Put(ctx, r); err != nil {
			t.Fatalf("file put: %v", err)
		}
	}

	pgM, err := pg.Metrics(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	fileM, err := file.Metrics(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if pgM != fileM {
		t.Fatalf("metrics differ by backend:\n  postgres %+v\n  file     %+v", pgM, fileM)
	}
	if pgM.Precision == 0 || pgM.Recall == 0 {
		t.Errorf("precision/recall came out zero: %+v", pgM)
	}
}

// The calibration verdict itself must not depend on where the evidence lives.
func TestCalibrationMatchesTheFileBackend(t *testing.T) {
	ctx := context.Background()
	pg := pgStore(t)
	file, err := New("")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 12; i++ {
		r := verdict("acme", "ap-"+string(rune('a'+i)), Confirmed)
		r.PredictedScore = 0.6
		if i%3 == 0 {
			r.Outcome = Refuted
		}
		if _, err := pg.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	pgCal, err := pg.Calibration(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	fileCal, err := file.Calibration(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if pgCal.Brier != fileCal.Brier || pgCal.ECE != fileCal.ECE || pgCal.Samples != fileCal.Samples {
		t.Fatalf("calibration differs by backend:\n  postgres brier=%v ece=%v n=%d\n  file     brier=%v ece=%v n=%d",
			pgCal.Brier, pgCal.ECE, pgCal.Samples, fileCal.Brier, fileCal.ECE, fileCal.Samples)
	}
}

// "Not recorded" and "recorded as not detected" are different claims, and the detection
// diagnostics distinguish them - so a NULL must survive the round trip as nil rather
// than collapsing to false.
func TestUnrecordedDetectionStaysNil(t *testing.T) {
	ctx := context.Background()
	s := pgStore(t)

	no := false
	unset := verdict("acme", "ap-unset", Confirmed)
	recorded := verdict("acme", "ap-recorded", Confirmed)
	recorded.Detected = &no

	for _, r := range []Record{unset, recorded} {
		if _, err := s.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	list, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list {
		switch r.PathID {
		case "ap-unset":
			if r.Detected != nil {
				t.Error("an unrecorded detection came back as recorded - absent evidence became evidence of absence")
			}
		case "ap-recorded":
			if r.Detected == nil || *r.Detected {
				t.Errorf("a recorded 'not detected' came back as %v", r.Detected)
			}
		}
	}
}

// Deleting evidence changes what the calibration is computed from, so removing
// something that is not there must be reported rather than shrugged off.
func TestDeletingAnAbsentVerdictIsReported(t *testing.T) {
	s := pgStore(t)
	if err := s.Delete(context.Background(), "acme", "vd-nope"); err == nil {
		t.Fatal("deleting a verdict that does not exist reported success")
	}
}

// Validation is shared with the file backend: evidence one accepts cannot be evidence
// the other would have refused, or the dataset differs by deployment.
func TestVerdictValidationMatchesTheFileBackend(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	for name, r := range map[string]Record{
		"bad outcome": {Tenant: "acme", PathID: "p", Outcome: Outcome("maybe"), Source: "x"},
		"no source":   {Tenant: "acme", PathID: "p", Outcome: Confirmed},
		"no path id":  {Tenant: "acme", Outcome: Confirmed, Source: "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Put(ctx, r); err == nil {
				t.Error("accepted unaccountable evidence")
			}
		})
	}
}

// Tenants must not read each other's evidence: a shared calibration dataset would mix
// two estates' outcomes into one accuracy claim.
func TestVerdictTenantsAreIsolated(t *testing.T) {
	s := pgStore(t)
	ctx := context.Background()
	for _, tenant := range []string{"acme", "globex"} {
		if _, err := s.Put(ctx, verdict(tenant, "ap-1", Confirmed)); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Tenant != "acme" {
		t.Errorf("acme sees %d verdicts: %+v", len(list), list)
	}
}
