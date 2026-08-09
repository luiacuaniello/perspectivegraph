package audit

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/luiacuaniello/perspectivegraph/internal/pgmigrate"
)

func pgLog(t *testing.T) (*PGLog, *sql.DB) {
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
	if _, err := db.Exec(`DELETE FROM audit_log`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	l, err := OpenPG(db)
	if err != nil {
		t.Fatal(err)
	}
	return l, db
}

// settled drains the queue and stops the writer. Appends are asynchronous - deliberately,
// see PGLog.queue - so a test that verified the chain without this would be reading a log
// that is still being written, and would fail on timing rather than on behaviour.
func settled(t *testing.T, l *PGLog) {
	t.Helper()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// slowSealer makes each append take a controllable amount of time, standing in for a
// database that is not keeping up.
type slowSealer struct{ per time.Duration }

func (s slowSealer) Seal(b []byte) ([]byte, error) { time.Sleep(s.per); return b, nil }
func (slowSealer) Open(b []byte) ([]byte, error)   { return b, nil }
func (slowSealer) Enabled() bool                   { return true }

// THE problem this store could not solve by repeating the earlier pattern. Each record
// carries the hash of the one before it, so two replicas appending at once would both
// read the same tail, both claim it as prev_hash, and fork the chain - after which
// verification reports tampering on a log nobody touched. That is worse than no audit
// log: it destroys trust in the one control whose job is to be trustworthy.
func TestConcurrentAppendsProduceOneUnbrokenChain(t *testing.T) {
	_, db := pgLog(t)
	ctx := context.Background()

	// Several "replicas" over the same database, appending at once.
	const writers, each = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			other, err := OpenPG(db)
			if err != nil {
				t.Error(err)
				return
			}
			for i := 0; i < each; i++ {
				other.Record(ctx, "api", fmt.Sprintf("user-%d", w), "admin", "acme",
					map[string]any{"i": i})
			}
			// Closing drains this replica's queue, so wg.Wait below means every append
			// has actually reached the database rather than merely been accepted.
			if err := other.Close(); err != nil {
				t.Error(err)
			}
		}(w)
	}
	wg.Wait()

	n, err := VerifyPG(ctx, db)
	if err != nil {
		t.Fatalf("the chain is broken after concurrent appends: %v", err)
	}
	if n != writers*each {
		t.Fatalf("verified %d records, want %d - appends were lost", n, writers*each)
	}
}

// Altering a record must be visible. This is the entire point of the chain.
func TestAlteringARecordIsDetected(t *testing.T) {
	l, db := pgLog(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		l.Record(ctx, "auth.deny", "mallory", "", "acme", map[string]any{"i": i})
	}
	settled(t, l)
	if _, err := VerifyPG(ctx, db); err != nil {
		t.Fatalf("a clean chain failed verification: %v", err)
	}

	if _, err := db.Exec(`UPDATE audit_log SET subject = 'alice' WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPG(ctx, db); err == nil {
		t.Fatal("an altered record passed verification")
	}
}

// Deleting a record must be visible too - and it is a different signature from an
// alteration: the sequence jumps, which no legitimate append can produce.
func TestDeletingARecordIsDetected(t *testing.T) {
	l, db := pgLog(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		l.Record(ctx, "api", "alice", "admin", "acme", nil)
	}
	settled(t, l)
	if _, err := db.Exec(`DELETE FROM audit_log WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyPG(ctx, db)
	if err == nil {
		t.Fatal("a deletion passed verification")
	}
	if !strings.Contains(err.Error(), "removed") {
		t.Errorf("the error does not name the deletion: %v", err)
	}
}

// A failed append must not consume a sequence number: a gap is indistinguishable from a
// deletion, so it would make an honest log look tampered with. This is why seq is
// assigned inside the transaction rather than by a Postgres sequence, which does not
// roll back.
func TestAFailedAppendLeavesNoGap(t *testing.T) {
	l, db := pgLog(t)
	ctx := context.Background()
	l.Record(ctx, "api", "alice", "admin", "acme", nil)

	// A field that cannot be marshalled fails the append after the tail was read.
	l.Record(ctx, "api", "bob", "admin", "acme", map[string]any{"bad": make(chan int)})

	l.Record(ctx, "api", "carol", "admin", "acme", nil)
	settled(t, l)

	n, err := VerifyPG(ctx, db)
	if err != nil {
		t.Fatalf("a failed append left the chain unverifiable: %v", err)
	}
	if n != 2 {
		t.Fatalf("verified %d records, want the 2 that succeeded", n)
	}
}

// An empty log verifies: a deployment that has recorded nothing yet is not tampered
// with, and reporting an error there would cry wolf on every fresh install.
func TestAnEmptyChainVerifies(t *testing.T) {
	_, db := pgLog(t)
	n, err := VerifyPG(context.Background(), db)
	if err != nil || n != 0 {
		t.Fatalf("empty log: n=%d err=%v", n, err)
	}
}

// The reason the appends are asynchronous at all.
//
// Record is called by the auth middleware on EVERY denied request, and an append takes a
// global advisory lock. Inline, that would serialise every replica's request path on one
// lock - hardest during a credential-stuffing run, when denials spike. The control meant
// to be watching the attack would become the thing that amplifies it.
func TestRecordDoesNotBlockOnASlowDatabase(t *testing.T) {
	_, db := pgLog(t)
	l, err := OpenPG(db, WithSealer(slowSealer{per: 5 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// 200 denials against a backend that needs ~1s to absorb them.
	start := time.Now()
	for i := 0; i < 200; i++ {
		l.Record(ctx, "auth.deny", "mallory", "", "acme", map[string]any{"i": i})
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("200 denials took %v to record - the request path is waiting for the database", elapsed)
	}
	t.Logf("200 denials recorded in %v", elapsed)

	settled(t, l)
	n, err := VerifyPG(ctx, db)
	if err != nil {
		t.Fatalf("the chain is broken: %v", err)
	}
	// Asynchronous must not mean lossy on a clean shutdown: Close drains.
	if n != 200 {
		t.Fatalf("verified %d records, want all 200 - a graceful shutdown dropped some", n)
	}
}

// Close must be safe to call more than once: it is wired to a defer in main, and a second
// call from a shutdown path must not panic on an already-closed channel.
func TestCloseIsIdempotent(t *testing.T) {
	l, _ := pgLog(t)
	l.Record(context.Background(), "api", "alice", "admin", "acme", nil)
	settled(t, l)
	if err := l.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// After Close the log must refuse loudly rather than panic. A send on the queue is still
// possible from an in-flight request during shutdown.
func TestRecordAfterCloseDoesNotPanic(t *testing.T) {
	l, _ := pgLog(t)
	settled(t, l)
	l.Record(context.Background(), "auth.deny", "mallory", "", "acme", nil)
}
