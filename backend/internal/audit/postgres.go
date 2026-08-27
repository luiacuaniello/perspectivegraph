package audit

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"github.com/luiacuaniello/perspectivegraph/internal/reqid"
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
		err := l.append(rec)
		if err == nil {
			return
		}
		// A failed append consumes no sequence number, so the chain re-links over the
		// hole and the verifier cannot see that anything is missing. Rather than let a
		// record vanish invisibly, chain a tombstone in its place: the WHAT and WHO
		// survive, the detail is replaced by the reason it could not be stored, and an
		// auditor sees an acknowledged gap instead of a log that lies about being whole.
		tomb := Record{
			Time:    rec.Time,
			Action:  rec.Action,
			Subject: rec.Subject,
			Role:    rec.Role,
			Tenant:  rec.Tenant,
			// Fixed, known-encodable fields: whatever broke the original must not break
			// its tombstone too.
			Fields: map[string]any{"audit_error": "the detail of this event could not be stored"},
		}
		if terr := l.append(tomb); terr != nil {
			// Both failed - the store is unreachable, not the record malformed.
			slog.Error("audit: record NOT written and NOT tombstoned - the trail has a silent gap",
				"action", rec.Action, "subject", rec.Subject, "tenant", rec.Tenant,
				"fields", fmt.Sprint(rec.Fields), "err", err, "tombstone_err", terr)
			return
		}
		slog.Error("audit: record detail could not be stored, a tombstone was chained in its place",
			"action", rec.Action, "subject", rec.Subject, "tenant", rec.Tenant,
			"fields", fmt.Sprint(rec.Fields), "err", err)
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
func (l *PGLog) Record(ctx context.Context, action, subject, role, tenant string, fields map[string]any) {
	if l == nil || l.db == nil {
		return
	}
	// The request id ties an audit entry back to the HTTP call that caused it, which the
	// threat model relies on. The file backend merges it in Record; this backend used to
	// ignore its context entirely and silently lost it.
	if id := reqid.FromContext(ctx); id != "" {
		merged := make(map[string]any, len(fields)+1)
		for k, v := range fields {
			merged[k] = v
		}
		merged["request_id"] = id
		fields = merged
	}
	// Sanitised BEFORE hashing, so the hash covers exactly what the database will store.
	// See storable: an unsanitised NUL made the INSERT fail, and a failed append leaves no
	// gap, so an attacker could delete their own entries and still pass verification.
	rec := Record{
		Time:    l.now().UTC().Truncate(storedPrecision),
		Action:  action,
		Subject: stripNUL(subject),
		Role:    role,
		Tenant:  stripNUL(tenant),
		Fields:  storableFields(fields),
	}
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
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// An empty table is not necessarily a new chain. Retention may have pruned every
		// record, and then the chain continues from the checkpoint rather than restarting
		// at 1 - restarting would leave the verifier expecting a sequence the log no
		// longer has, and reporting the honest gap as tampering.
		if cerr := tx.QueryRowContext(ctx,
			`SELECT pruned_through_seq, pruned_through_hash FROM audit_log_checkpoint`).
			Scan(&lastSeq, &lastHash); cerr != nil && !errors.Is(cerr, sql.ErrNoRows) {
			return fmt.Errorf("read retention checkpoint: %w", cerr)
		}
	case err != nil:
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
//
// The ciphertext is base64'd into a JSON string because the column is jsonb, and AES-GCM
// output is arbitrary binary - nonce and tag included. Handing those bytes to jsonb
// directly made EVERY append fail as malformed JSON, so a deployment that set
// STORE_ENCRYPTION_KEY together with the Postgres backend wrote no audit records at all
// and, by the same no-gap property, still verified clean. The file backend already
// base64s its sealed lines; this matches it.
func (l *PGLog) sealFields(raw []byte) ([]byte, error) {
	if l.sealer == nil || !l.sealer.Enabled() {
		return raw, nil
	}
	sealed, err := l.sealer.Seal(raw)
	if err != nil {
		return nil, fmt.Errorf("seal fields: %w", err)
	}
	wrapped, err := json.Marshal(base64.StdEncoding.EncodeToString(sealed))
	if err != nil {
		return nil, fmt.Errorf("wrap sealed fields: %w", err)
	}
	return wrapped, nil
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

// Checkpoint records how far retention has pruned the chain, and the hash of the last
// record it removed. A log that has never been pruned has no checkpoint.
type Checkpoint struct {
	PrunedThroughSeq  int64
	PrunedThroughHash string
	PrunedRecords     int64
	PrunedAt          time.Time
}

// ReadCheckpointPG returns the retention checkpoint, or ok=false if the log has never
// been pruned. Callers use it to say what a verification actually covered: "N records
// verified" means something different when M older ones were deliberately removed.
func ReadCheckpointPG(ctx context.Context, db *sql.DB) (cp Checkpoint, ok bool, err error) {
	if db == nil {
		return Checkpoint{}, false, errors.New("audit: nil database handle")
	}
	err = db.QueryRowContext(ctx, `
		SELECT pruned_through_seq, pruned_through_hash, pruned_records, pruned_at
		FROM audit_log_checkpoint`).
		Scan(&cp.PrunedThroughSeq, &cp.PrunedThroughHash, &cp.PrunedRecords, &cp.PrunedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, err
	}
	return cp, true, nil
}

// PruneBefore deletes records older than cutoff and moves the retention checkpoint,
// reporting how many it removed.
//
// It prunes a PREFIX of the chain and nothing else. That restriction is the whole design:
// records leave in the order they arrived, the checkpoint keeps the hash of the last one
// removed, and what survives still verifies link-by-link back to that checkpoint. Deleting
// from the middle would be indistinguishable from an attacker erasing their own entry, so
// it is not offered.
//
// It takes the same advisory lock an append does, so retention cannot run between an
// appender reading the tail and writing its record.
func (l *PGLog) PruneBefore(ctx context.Context, cutoff time.Time) (removed int64, err error) {
	if l == nil || l.db == nil {
		return 0, nil
	}
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockKey); err != nil {
		return 0, fmt.Errorf("acquire audit lock: %w", err)
	}

	// The newest record that is old enough to go. Everything at or below its seq leaves,
	// and its hash becomes what the survivors chain back to.
	var (
		throughSeq  int64
		throughHash string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT seq, hash FROM audit_log WHERE at < $1 ORDER BY seq DESC LIMIT 1`, cutoff.UTC()).
		Scan(&throughSeq, &throughHash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil // nothing old enough
	}
	if err != nil {
		return 0, fmt.Errorf("find retention cutoff: %w", err)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE seq <= $1`, throughSeq)
	if err != nil {
		return 0, fmt.Errorf("prune audit log: %w", err)
	}
	removed, err = res.RowsAffected()
	if err != nil {
		return 0, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log_checkpoint (id, pruned_through_seq, pruned_through_hash, pruned_records, pruned_at)
		VALUES (true, $1, $2, $3, now())
		ON CONFLICT (id) DO UPDATE SET
			pruned_through_seq  = EXCLUDED.pruned_through_seq,
			pruned_through_hash = EXCLUDED.pruned_through_hash,
			pruned_records      = audit_log_checkpoint.pruned_records + EXCLUDED.pruned_records,
			pruned_at           = EXCLUDED.pruned_at`,
		throughSeq, throughHash, removed); err != nil {
		return 0, fmt.Errorf("move retention checkpoint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	// The prune is itself an auditable act, so it goes into the chain it just shortened -
	// after the commit, because Record queues and would otherwise deadlock on the lock
	// this transaction is holding.
	l.Record(ctx, "audit.prune", "retention", "", "", map[string]any{
		"removed": removed, "through_seq": throughSeq, "cutoff": cutoff.UTC().Format(time.RFC3339),
	})
	return removed, nil
}

// VerifyPG walks the chain and reports how many records held.
//
// It recomputes each record's hash from its contents and checks that every link points
// at the record before it, which is what makes a deletion visible: removing a record
// leaves the next one pointing at a hash that is no longer there.
//
// Retention is the one deletion that is allowed, and it is not taken on trust: the chain
// is expected to start at record 1 unless a checkpoint says a prefix was pruned, in which
// case it must resume exactly where the checkpoint left off, at the hash it recorded. A
// forged checkpoint therefore cannot hide a deletion - it can only move where the chain is
// expected to start, and the survivors still have to link to the hash it names.
func VerifyPG(ctx context.Context, db *sql.DB, opts ...Option) (records int, err error) {
	if db == nil {
		return 0, errors.New("audit: nil database handle")
	}
	sealer := sealerFrom(opts)

	prev := ""
	var expectSeq int64 = 1
	cp, pruned, err := ReadCheckpointPG(ctx, db)
	if err != nil {
		return 0, fmt.Errorf("read retention checkpoint: %w", err)
	}
	if pruned {
		expectSeq = cp.PrunedThroughSeq + 1
		prev = cp.PrunedThroughHash
	}

	rows, err := db.QueryContext(ctx, `
		SELECT seq, at, action, subject, role, tenant, fields, prev_hash, hash
		FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

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
	var encoded string
	if err := json.Unmarshal(b, &encoded); err != nil {
		return nil, fmt.Errorf("sealed fields are not a JSON string: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("sealed fields are not base64: %w", err)
	}
	return sealer.Open(sealed)
}
