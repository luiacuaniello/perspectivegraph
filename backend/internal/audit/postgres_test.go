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
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
	"github.com/luiacuaniello/perspectivegraph/internal/pgmigrate"
	"github.com/luiacuaniello/perspectivegraph/internal/reqid"
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

// A failed append must not consume a sequence number - a gap is indistinguishable from a
// deletion, so it would make an honest log look tampered with. That is why seq is assigned
// inside the transaction rather than by a Postgres sequence, which does not roll back.
//
// But "no gap" alone means a dropped record is INVISIBLE: the chain re-links over it and
// the verifier certifies a log that is missing an event. So the event is tombstoned
// instead - the action and subject survive, the unstorable detail is replaced, and an
// auditor sees an acknowledged loss rather than a log that lies about being whole.
func TestAFailedAppendIsTombstonedNotDropped(t *testing.T) {
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
	if n != 3 {
		t.Fatalf("verified %d records, want 3 - the event whose detail failed must still be chained", n)
	}

	var subject, marker string
	if err := db.QueryRow(
		`SELECT subject, coalesce(fields->>'audit_error','') FROM audit_log WHERE seq = 2`).
		Scan(&subject, &marker); err != nil {
		t.Fatal(err)
	}
	if subject != "bob" {
		t.Errorf("tombstone subject = %q, want the subject of the event that failed", subject)
	}
	if marker == "" {
		t.Error("the tombstone does not say the detail could not be stored")
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
	// Verified with the same sealer it was written with: sealed fields are base64 inside
	// the jsonb column, so a verifier without the key cannot read them - which is the
	// point of sealing them.
	n, err := VerifyPG(ctx, db, WithSealer(slowSealer{}))
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

// The bug a Linux CI run caught and this Mac hid.
//
// The hash covers the record's timestamp. Go's clock carries nanoseconds on Linux;
// PostgreSQL's timestamptz keeps microseconds. Hashing the untruncated value produced
// records that could never re-verify - every one of them came back "contents do not
// match its hash - it was altered", on a log nobody had touched.
//
// The clock is pinned rather than read, so this fails on any host: on a platform whose
// clock is already microsecond-granular (macOS) the defect is otherwise invisible, which
// is exactly how it reached CI.
func TestNanosecondTimestampsStillVerify(t *testing.T) {
	l, db := pgLog(t)
	// A time with nanoseconds Postgres cannot keep: ...123456789 truncates to ...123456.
	pinned := time.Date(2026, 8, 9, 12, 0, 0, 123456789, time.UTC)
	l.now = func() time.Time { return pinned }

	l.Record(context.Background(), "auth.deny", "mallory", "", "acme", map[string]any{"i": 1})
	settled(t, l)

	if _, err := VerifyPG(context.Background(), db); err != nil {
		t.Fatalf("a record written with a nanosecond clock does not verify: %v", err)
	}

	// And the stored instant must be the truncated one, not a rounded or shifted one.
	var got time.Time
	if err := db.QueryRow(`SELECT at FROM audit_log WHERE seq = 1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if want := pinned.Truncate(time.Microsecond); !got.UTC().Equal(want) {
		t.Errorf("stored %s, want %s", got.UTC().Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}

// A NUL byte in an attacker-reachable field must not be able to delete the record.
//
// The audit fields carry r.URL.Path, recorded by RequireRole on a denial BEFORE
// authentication succeeds, and Go's ServeMux passes a percent-encoded NUL straight into a
// wildcard segment. Go marshals it as a JSON escape that jsonb rejects (22P05), so the
// INSERT failed - and because a rolled-back append consumes no sequence number, the next
// record took the seq the dropped one would have had and the chain re-linked over the
// hole. VerifyPG then certified a log an unauthenticated attacker had edited.
func TestNULInFieldsCannotDeleteARecord(t *testing.T) {
	l, db := pgLog(t)
	ctx := context.Background()

	l.Record(ctx, "auth.deny", "unknown", "", "acme", map[string]any{"path": "/suppressions/a"})
	l.Record(ctx, "auth.deny", "unknown", "", "acme", map[string]any{"path": "/suppressions/b\x00"})
	l.Record(ctx, "auth.deny", "unknown", "", "acme", map[string]any{"path": "/suppressions/c"})
	settled(t, l)

	n, err := VerifyPG(ctx, db)
	if err != nil {
		t.Fatalf("chain broken: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d records, want 3 - the attacker's request erased its own audit entry", n)
	}

	// The surviving record must still name the path, minus the byte that cannot be stored.
	var stored string
	if err := db.QueryRow(
		`SELECT fields->>'path' FROM audit_log WHERE seq = 2`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "/suppressions/b" {
		t.Errorf("stored path %q, want the sanitised path", stored)
	}
}

// A NUL in the subject or tenant is the same attack through a different field.
func TestNULInSubjectAndTenantIsSanitised(t *testing.T) {
	l, db := pgLog(t)
	l.Record(context.Background(), "api", "alice\x00", "admin", "acme\x00", nil)
	settled(t, l)
	if _, err := VerifyPG(context.Background(), db); err != nil {
		t.Fatalf("chain broken: %v", err)
	}
	var subject, tenant string
	if err := db.QueryRow(`SELECT subject, tenant FROM audit_log WHERE seq = 1`).Scan(&subject, &tenant); err != nil {
		t.Fatal(err)
	}
	if subject != "alice" || tenant != "acme" {
		t.Errorf("stored subject=%q tenant=%q, want them sanitised", subject, tenant)
	}
}

// Encryption at rest must not silently disable the audit log.
//
// The sealer returns raw AES-GCM output - binary, nonce and tag included - and the column
// is jsonb. Storing those bytes directly made every append fail as malformed JSON, so a
// deployment with STORE_ENCRYPTION_KEY plus the Postgres backend recorded NOTHING, and by
// the no-gap property the empty chain still verified clean.
func TestSealedFieldsRoundTripThroughJSONB(t *testing.T) {
	_, db := pgLog(t)
	sealer, err := cryptostore.New(strings.Repeat("ab", 32)) // 64 hex chars = 32-byte key
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	l, err := OpenPG(db, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	l.Record(ctx, "auth.deny", "mallory", "", "acme", map[string]any{"path": "/graphql", "remote": "203.0.113.9"})
	settled(t, l)

	n, err := VerifyPG(ctx, db, WithSealer(sealer))
	if err != nil {
		t.Fatalf("a sealed chain does not verify: %v", err)
	}
	if n != 1 {
		t.Fatalf("verified %d records, want 1 - encryption at rest silently dropped the audit trail", n)
	}

	// And the plaintext must genuinely not be in the column.
	var raw string
	if err := db.QueryRow(`SELECT fields::text FROM audit_log WHERE seq = 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "203.0.113.9") {
		t.Errorf("the remote address is stored in clear despite a configured key: %s", raw)
	}
}

// The request id ties an entry to the HTTP call that caused it. This backend ignored its
// context and dropped it.
func TestRequestIDReachesThePostgresLog(t *testing.T) {
	l, db := pgLog(t)
	ctx := reqid.NewContext(context.Background(), "req-abc123")
	l.Record(ctx, "api", "alice", "admin", "acme", map[string]any{"path": "/graphql"})
	settled(t, l)

	var got string
	if err := db.QueryRow(`SELECT fields->>'request_id' FROM audit_log WHERE seq = 1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "req-abc123" {
		t.Errorf("request_id = %q, want it carried onto the record", got)
	}
	if _, err := VerifyPG(context.Background(), db); err != nil {
		t.Fatalf("chain broken: %v", err)
	}
}
