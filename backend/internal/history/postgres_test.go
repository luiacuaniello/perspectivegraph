package history

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
	for _, tbl := range []string{"history_paths", "history_posture", "history_calibration"} {
		if _, err := db.Exec("DELETE FROM " + tbl); err != nil {
			t.Fatalf("reset %s: %v", tbl, err)
		}
	}
	s, err := NewPG(db, time.Millisecond, 100)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// THE reason this store had to move. The analyzer is leader-gated, so only one replica
// ever writes - but a replica that is NOT the leader holds an empty in-memory history,
// so the trend chart is full or blank depending on which pod answered the request.
func TestANonLeaderReplicaSeesTheSameHistory(t *testing.T) {
	leader := pgStore(t)
	follower, err := NewPG(leader.db, time.Millisecond, 100)
	if err != nil {
		t.Fatal(err)
	}

	leader.ObservePass("acme", []Observation{{ID: "ap-1", Route: "lb -> db", Score: 0.7}}, 42)

	if _, ok := follower.Get("acme", "ap-1"); !ok {
		t.Fatal("the follower cannot see the path the leader recorded - the panel is blank on half the pods")
	}
	if got := follower.Trend("acme", 10); len(got) == 0 {
		t.Error("the follower's trend chart is empty while the leader's is not")
	}
	if st := follower.Stats("acme"); st.OpenPaths != 1 {
		t.Errorf("follower stats show %d open paths, want 1", st.OpenPaths)
	}
}

// A path that vanishes from a pass is resolved, which is what MTTR averages over. Get
// this wrong and a number people plan work against is silently invented.
func TestVanishedPathIsResolvedAndFeedsMTTR(t *testing.T) {
	s := pgStore(t)
	s.ObservePass("acme", []Observation{{ID: "ap-1"}, {ID: "ap-2"}}, 10)
	time.Sleep(20 * time.Millisecond)
	s.ObservePass("acme", []Observation{{ID: "ap-2"}}, 5)

	rec, ok := s.Get("acme", "ap-1")
	if !ok {
		t.Fatal("the resolved path disappeared entirely")
	}
	if rec.Open || rec.ResolvedAt == nil {
		t.Fatalf("ap-1 vanished from the pass but is still open: %+v", rec)
	}
	if other, _ := s.Get("acme", "ap-2"); !other.Open {
		t.Error("ap-2 was still present but got resolved")
	}

	st := s.Stats("acme")
	if st.OpenPaths != 1 || st.ResolvedPaths != 1 || st.MTTRCount != 1 {
		t.Errorf("stats = %+v, want 1 open / 1 resolved / 1 MTTR sample", st)
	}
	if st.MTTRSeconds <= 0 {
		t.Error("MTTR is zero for a path that was open then resolved")
	}
}

// A path that comes back is a REGRESSION, not a continuation: first_seen restarts so
// "open for" describes this occurrence rather than the original one, and the reopen is
// counted. Treating it as continuous would make a recurring problem look like one long
// unattended one.
func TestAReturningPathCountsAsAReopen(t *testing.T) {
	s := pgStore(t)
	s.ObservePass("acme", []Observation{{ID: "ap-1"}}, 10)
	first, _ := s.Get("acme", "ap-1")

	time.Sleep(20 * time.Millisecond)
	s.ObservePass("acme", nil, 0) // resolved
	time.Sleep(20 * time.Millisecond)
	s.ObservePass("acme", []Observation{{ID: "ap-1"}}, 10) // back

	back, ok := s.Get("acme", "ap-1")
	if !ok {
		t.Fatal("the path did not come back")
	}
	if back.Reopens != 1 {
		t.Errorf("reopens = %d, want 1", back.Reopens)
	}
	if !back.FirstSeen.After(first.FirstSeen) {
		t.Error("first_seen did not restart, so 'open for' would report the original occurrence")
	}
	if !back.Open || back.ResolvedAt != nil {
		t.Errorf("the returned path is not open again: %+v", back)
	}
}

// The trend coalesces to one point per window, anchored to the window's start. Sliding
// the anchor forward on each refresh would mean a busy tenant never appends at all, and
// the chart would be a single perpetually-updated point instead of a line.
func TestTrendCoalescesWithinTheWindow(t *testing.T) {
	s := pgStore(t)
	s.sampleEvery = time.Hour // everything falls in one window

	s.SampleTrend("acme", 5, 10)
	s.SampleTrend("acme", 9, 20)
	s.SampleTrend("acme", 12, 30)

	pts := s.Trend("acme", 100)
	if len(pts) != 1 {
		t.Fatalf("%d points inside one window, want 1 coalesced", len(pts))
	}
	if pts[0].CriticalPaths != 12 || pts[0].RiskPct != 30 {
		t.Errorf("the coalesced point kept stale values: %+v", pts[0])
	}
}

// Tenants must not see each other's trend or lifecycle.
func TestHistoryTenantsAreIsolated(t *testing.T) {
	s := pgStore(t)
	s.ObservePass("acme", []Observation{{ID: "ap-1"}}, 10)
	s.ObservePass("globex", []Observation{{ID: "ap-2"}}, 20)

	if _, ok := s.Get("acme", "ap-2"); ok {
		t.Error("acme can read globex's path record")
	}
	if st := s.Stats("acme"); st.OpenPaths != 1 {
		t.Errorf("acme sees %d open paths, want its own 1", st.OpenPaths)
	}
}

// The calibration trend is the same shape, and it is what an operator watches while a
// calibration programme accumulates evidence.
func TestCalibrationTrendIsRecorded(t *testing.T) {
	s := pgStore(t)
	s.SampleCalibration("acme", 0.21, 0.09, 14)
	pts := s.CalibrationTrend("acme", 10)
	if len(pts) != 1 {
		t.Fatalf("%d calibration points, want 1", len(pts))
	}
	if pts[0].Samples != 14 || pts[0].Brier != 0.21 {
		t.Errorf("point = %+v", pts[0])
	}
}
