package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// auditLockKey is the advisory lock every append serialises on. Transaction-scoped, so
// it is released by COMMIT or ROLLBACK - a replica that dies mid-append cannot wedge the
// log for everyone else.
const auditLockKey int64 = 8_040_192_255_102

// PGLog is the tamper-evident audit log, in PostgreSQL.
//
// A hash chain is only evidence if each record's predecessor is settled before the next
// one is written. Two replicas appending at once would both read the same tail, both
// claim it as prev_hash, and fork the chain - after which Verify reports tampering on a
// log nobody touched. That failure is worse than having no audit log: it destroys trust
// in the one control whose whole job is to be trustworthy.
//
// So appends take a transaction-scoped advisory lock, read the tail, and write inside
// that same transaction - and because that lock is global, appends run through a queue
// and a single writer per replica rather than inline on the request that caused them.
// See the queue field for why that matters more than it looks.
type PGLog struct {
	db     *sql.DB
	sealer sealerLike

	// queue decouples the append from the request that caused it.
	//
	// Record is called synchronously by the auth middleware on every denied request.
	// Appending here takes a GLOBAL advisory lock, so doing that inline would serialise
	// every replica's request path on one lock - and it would do so hardest during a
	// credential-stuffing run, when denials spike. A security tool must not become a
	// denial-of-service amplifier at the exact moment it is under attack.
	//
	// The cost is that a crash can lose what is still queued. That is why a full queue
	// is NOT a silent drop: it is counted and logged at error level, because an audit
	// record that vanishes without trace is worse than one that arrives late.
	queue     chan Record
	done      chan struct{}
	closed    chan struct{}
	closeOnce sync.Once

	// now exists so a test can pin the clock. The platform's clock granularity is
	// load-bearing here (see storedPrecision), and on a host whose clock is already
	// coarse the bug this guards against is invisible.
	now func() time.Time
}

// storedPrecision is the resolution PostgreSQL keeps in a timestamptz column.
//
// The record's hash covers its timestamp, so the hash MUST be computed over the value
// the database will actually return - not the one Go happened to read from the clock.
// Go's time.Now() carries nanoseconds on Linux; timestamptz keeps microseconds. Hashing
// the untruncated value therefore produced a record that could never re-verify: every
// entry came back reporting "contents do not match its hash - it was altered", on a log
// nobody had touched. A tamper-evident log that cries wolf on every record is worse than
// none, because the one time it is right, nobody is listening.
//
// It was invisible on macOS, whose clock is already microsecond-granular, and it took a
// Linux CI run to surface it.
const storedPrecision = time.Microsecond

// queueDepth bounds the buffer. Deep enough to absorb a burst of denials, shallow enough
// that a database outage surfaces as loud drops within seconds rather than as unbounded
// memory growth.
const queueDepth = 4096

// sealerLike is the encryption hook the file log already has. Sealing is applied to the
// FIELDS only here: the chain columns must stay readable for the database to order and
// verify them, and the fields are where anything sensitive would be.
type sealerLike interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
	Enabled() bool
}

// OpenPG builds a Postgres-backed audit log.
func OpenPG(db *sql.DB, opts ...Option) (*PGLog, error) {
	if db == nil {
		return nil, errors.New("audit: nil database handle")
	}
	l := &PGLog{
		db:     db,
		now:    time.Now,
		sealer: sealerFrom(opts),
		queue:  make(chan Record, queueDepth),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	// ONE writer per replica. The advisory lock is then almost always uncontended
	// within a process, and contention across replicas is bounded by their count
	// rather than by their request rate.
	go l.drain()
	return l, nil
}

// drain is the single writer. It holds the chain's ordering for this replica and takes
// the cross-replica lock once per record.
//
// The queue is never closed. Closing it would race with Record: a concurrent send on a
// closed channel panics, and doing that on the audit path during shutdown would take the
// process down while recording why it was going down. Shutdown is signalled on its own
// channel instead, after which the drainer empties what is buffered and stops.
func (l *PGLog) drain() {
	defer close(l.done)
	write := func(rec Record) {
		if err := l.append(rec); err != nil {
			// Loud: a lost audit record is the one loss that must never be quiet.
			slog.Error("audit: record NOT written", "action", rec.Action, "subject", rec.Subject, "err", err)
		}
	}
	for {
		select {
		case rec := <-l.queue:
			write(rec)
		case <-l.closed:
			// Empty whatever is still buffered before giving up.
			for {
				select {
				case rec := <-l.queue:
					write(rec)
				default:
					return
				}
			}
		}
	}
}

// Record appends one entry, linking it to the previous one.
//
// Failures are logged rather than returned, exactly as the file log does: an audit write
// must never fail the request it is recording, or an attacker could suppress their own
// trail by making the log unwritable.
func (l *PGLog) Record(_ context.Context, action, subject, role, tenant string, fields map[string]any) {
	if l == nil || l.db == nil {
		return
	}
	rec := Record{Time: l.now().UTC().Truncate(storedPrecision), Action: action, Subject: subject, Role: role, Tenant: tenant, Fields: fields}
	select {
	case <-l.closed:
		slog.Error("audit: record NOT written, the log is closed", "action", action, "subject", subject)
	case l.queue <- rec:
	default:
		// The queue is full: the database is not keeping up. Refusing loudly beats
		// blocking the request path, and beats dropping in silence.
		slog.Error("audit: queue full, record DROPPED - the audit trail is incomplete",
			"action", action, "subject", subject, "depth", queueDepth)
	}
}

func (l *PGLog) append(rec Record) error {
	// The writer owns its own context: the request that caused this record may be long
	// gone, and its cancellation must not abandon the record of what it did.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Serialise: without this two replicas read the same tail and fork the chain.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockKey); err != nil {
		return fmt.Errorf("acquire audit lock: %w", err)
	}

	var (
		lastSeq  int64
		lastHash string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read chain tail: %w", err)
	}

	// Seq and the chain link are assigned HERE, not when the record was queued: the
	// chain's order is the order it was written in, which is the only order the
	// verifier can check.
	rec.Seq = lastSeq + 1
	rec.PrevHash = lastHash
	// The hash covers the record as the file log hashes it, so a log migrated from one
	// backend to the other still verifies.
	rec.Hash = hashRecord(rec)

	raw, err := json.Marshal(rec.Fields)
	if err != nil {
		return fmt.Errorf("encode fields: %w", err)
	}
	stored, err := l.sealFields(raw)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log (seq, at, action, subject, role, tenant, fields, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		rec.Seq, rec.Time, rec.Action, rec.Subject, rec.Role, rec.Tenant, stored,
		rec.PrevHash, rec.Hash); err != nil {
		return fmt.Errorf("append record %d: %w", rec.Seq, err)
	}
	return tx.Commit()
}

// sealFields encrypts the fields blob when a key is configured. The chain columns stay
// in the clear: the database has to order and compare them, and an operator verifying
// the chain must be able to do so without the key.
func (l *PGLog) sealFields(raw []byte) ([]byte, error) {
	if l.sealer == nil || !l.sealer.Enabled() {
		return raw, nil
	}
	sealed, err := l.sealer.Seal(raw)
	if err != nil {
		return nil, fmt.Errorf("seal fields: %w", err)
	}
	return sealed, nil
}

// Close stops accepting records and waits for the queue to drain, so a graceful
// shutdown does not discard what is already in flight. The pool itself is owned by the
// caller, which shares it with the other governance stores.
func (l *PGLog) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() { close(l.closed) })
	select {
	case <-l.done:
	case <-time.After(15 * time.Second):
		slog.Error("audit: the queue did not drain before shutdown - records were lost")
	}
	return nil
}

// VerifyPG walks the chain and reports how many records held.
//
// It recomputes each record's hash from its contents and checks that every link points
// at the record before it, which is what makes a deletion visible: removing a record
// leaves the next one pointing at a hash that is no longer there.
func VerifyPG(ctx context.Context, db *sql.DB, opts ...Option) (records int, err error) {
	if db == nil {
		return 0, errors.New("audit: nil database handle")
	}
	sealer := sealerFrom(opts)

	rows, err := db.QueryContext(ctx, `
		SELECT seq, at, action, subject, role, tenant, fields, prev_hash, hash
		FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	prev := ""
	var expectSeq int64 = 1
	for rows.Next() {
		var (
			rec    Record
			fields []byte
		)
		if err := rows.Scan(&rec.Seq, &rec.Time, &rec.Action, &rec.Subject, &rec.Role,
			&rec.Tenant, &fields, &rec.PrevHash, &rec.Hash); err != nil {
			return records, err
		}
		// A gap is indistinguishable from a deletion, so it is one.
		if rec.Seq != expectSeq {
			return records, fmt.Errorf("record %d: sequence jumps to %d - %d record(s) removed",
				expectSeq, rec.Seq, rec.Seq-expectSeq)
		}
		if rec.PrevHash != prev {
			return records, fmt.Errorf("record %d: prev_hash does not match the record before it", rec.Seq)
		}

		opened, err := openFields(fields, sealer)
		if err != nil {
			return records, fmt.Errorf("record %d: %w", rec.Seq, err)
		}
		if len(opened) > 0 && string(opened) != "null" {
			if err := json.Unmarshal(opened, &rec.Fields); err != nil {
				return records, fmt.Errorf("record %d: decode fields: %w", rec.Seq, err)
			}
		}

		want := rec.Hash
		rec.Time = rec.Time.UTC()
		if got := hashRecord(rec); got != want {
			return records, fmt.Errorf("record %d: contents do not match its hash - it was altered", rec.Seq)
		}
		prev = want
		expectSeq++
		records++
	}
	return records, rows.Err()
}

func openFields(b []byte, sealer sealerLike) ([]byte, error) {
	if sealer == nil || !sealer.Enabled() {
		return b, nil
	}
	return sealer.Open(b)
}
