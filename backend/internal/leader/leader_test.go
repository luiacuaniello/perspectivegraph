package leader

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestAlwaysLeaderIsAlwaysLeader(t *testing.T) {
	if !(AlwaysLeader{}).IsLeader(context.Background()) {
		t.Fatal("AlwaysLeader must always be the leader")
	}
}

func TestNewPostgresKeyIsStablePerRole(t *testing.T) {
	// The advisory-lock key is a pure function of the role, so every replica of
	// the same singleton contends on the *same* lock, and different singletons
	// (e.g. "analyzer" vs "pruner") never collide.
	a, err := NewPostgres("host=127.0.0.1 sslmode=disable", "analyzer")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewPostgres("host=127.0.0.1 sslmode=disable", "analyzer")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c, err := NewPostgres("host=127.0.0.1 sslmode=disable", "pruner")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if a.key != b.key {
		t.Errorf("same role yielded different keys: %d vs %d", a.key, b.key)
	}
	if a.key == c.key {
		t.Errorf("different roles collided on key %d", a.key)
	}
}

func TestIsLeaderFailsClosedWhenUnreachable(t *testing.T) {
	// A DB it can't reach must make IsLeader return false (never block forever,
	// never panic) — better to skip an at-most-once action than to deadlock or
	// crash the analyzer pass.
	p, err := NewPostgres("host=127.0.0.1 port=1 connect_timeout=1 sslmode=disable", "analyzer")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- p.IsLeader(ctx) }()
	select {
	case leader := <-done:
		if leader {
			t.Fatal("unreachable DB must not be reported as leader")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("IsLeader blocked on an unreachable DB instead of failing closed")
	}
}

// TestAdvisoryLockMutualExclusion exercises the real Postgres advisory lock: of
// two electors on the same role only one is leader, and leadership fails over
// when the holder releases. Gated on a test DB (the CI AGE job provides one).
func TestAdvisoryLockMutualExclusion(t *testing.T) {
	dsn := os.Getenv("PERSPECTIVE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set PERSPECTIVE_TEST_POSTGRES_DSN to run the advisory-lock integration test")
	}
	role := fmt.Sprintf("test-%d", time.Now().UnixNano())
	ctx := context.Background()

	a, err := NewPostgres(dsn, role)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewPostgres(dsn, role)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if !a.IsLeader(ctx) {
		t.Fatal("first elector should acquire the lock")
	}
	if a.IsLeader(ctx) != true {
		t.Fatal("the holder should remain leader on a re-check")
	}
	if b.IsLeader(ctx) {
		t.Fatal("second elector must not be leader while the first holds the lock")
	}

	// The holder releases (connection closed) → the other takes over.
	if err := a.Close(); err != nil {
		t.Fatalf("close leader: %v", err)
	}
	acquired := false
	for i := 0; i < 50; i++ { // give Postgres a moment to release on backend exit
		if b.IsLeader(ctx) {
			acquired = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !acquired {
		t.Fatal("second elector should acquire leadership after the first released")
	}
}
