package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// hdrSnapshot marks every message of a batch that carries a complete snapshot, so the
// message that completes the batch - whichever event it belongs to - knows a sweep is due.
const hdrSnapshot = "Pg-Snapshot"

// Sweeper applies a complete snapshot's omissions (normalization.Normalizer.Sweep).
type Sweeper func(ctx context.Context, tenant, source, scope string, taken time.Time) error

// WithSweeper makes the consumer apply complete snapshots: once every message of an
// ingest that declared one has reached the graph, what its source no longer lists is
// retracted. Nil (the default) records nothing and retracts nothing.
func (b *Broker) WithSweeper(fn Sweeper) *Broker {
	b.sweeper = fn
	return b
}

// snapshotRecord is one (source, scope) a batch described in full.
type snapshotRecord struct {
	Tenant string    `json:"tenant"`
	Source string    `json:"source"`
	Scope  string    `json:"scope"`
	Taken  time.Time `json:"taken"`
}

// snapshotKey names a batch's record of one (source, scope). Not under "<id>.", which
// BatchStatus counts as applied messages.
func snapshotKey(id string, ev ontology.Event) string {
	sum := sha256.Sum256([]byte(ev.Tenant + "\x00" + ev.Source + "\x00" + ev.Snapshot.Scope))
	return "snap." + id + "." + hex.EncodeToString(sum[:8])
}

// recordSnapshot notes, before the message is marked applied, that its batch described
// ev's scope in full. Every chunk of the event writes the same key.
func (b *Broker) recordSnapshot(ctx context.Context, h nats.Header, ev ontology.Event) {
	id, kv := h.Get(hdrBatch), b.batches()
	if b.sweeper == nil || ev.CompleteSnapshot() == nil || kv == nil || !batchIDRe.MatchString(id) {
		return // by the rule the normalizer recorded the event's origins by
	}
	rec, err := json.Marshal(snapshotRecord{Tenant: ev.Tenant, Source: ev.Source, Scope: ev.Snapshot.Scope, Taken: ev.Snapshot.Taken})
	if err != nil {
		return
	}
	if _, err := kv.Put(context.WithoutCancel(ctx), snapshotKey(id, ev), rec); err != nil {
		slog.Warn("could not record a complete snapshot; nothing it omits will be retracted",
			"batch", id, "source", ev.Source, "scope", ev.Snapshot.Scope, "err", err)
	}
}

// maybeSweep runs the sweeps of a snapshot batch once all of its messages are applied.
// Exactly one replica does: the first to create the batch's "swept" key. It runs after
// the message is acknowledged, so a long sweep never turns into a redelivery.
//
// Best effort, and it errs towards keeping: a batch that never completes - a message
// dead-lettered, an applied mark that failed to record - retracts nothing, and a sweep
// lost to a crash is done by the next snapshot of the same scope, which retracts
// everything older than itself.
func (b *Broker) maybeSweep(ctx context.Context, h nats.Header) {
	id, kv := h.Get(hdrBatch), b.batches()
	if b.sweeper == nil || h.Get(hdrSnapshot) == "" || kv == nil || !batchIDRe.MatchString(id) {
		return
	}
	ctx = context.WithoutCancel(ctx)
	if complete, err := b.batchComplete(ctx, kv, id); err != nil || !complete {
		return
	}
	if _, err := kv.Create(ctx, "swept."+id, []byte("1")); err != nil {
		return // another replica is sweeping it - or the bucket is unreachable, and keeping is the safe side
	}
	lister, err := kv.ListKeysFiltered(ctx, "snap."+id+".*")
	if err != nil {
		slog.Warn("could not read a batch's complete snapshots; nothing will be retracted", "batch", id, "err", err)
		return
	}
	for key := range lister.Keys() {
		e, err := kv.Get(ctx, key)
		if err != nil {
			continue
		}
		var rec snapshotRecord
		if err := json.Unmarshal(e.Value(), &rec); err != nil || rec.Scope == "" {
			continue
		}
		if err := b.sweeper(ctx, rec.Tenant, rec.Source, rec.Scope, rec.Taken); err != nil {
			slog.Error("complete snapshot: sweep failed; the next snapshot of this scope will retry it",
				"tenant", rec.Tenant, "source", rec.Source, "scope", rec.Scope, "err", err)
		}
	}
}

// batchComplete reports whether every message of a batch has been applied. It counts
// the keys only, unlike BatchStatus, which also reads each one's time: it runs after
// every message of a snapshot batch, and a large batch would make that quadratic.
func (b *Broker) batchComplete(ctx context.Context, kv jetstream.KeyValue, id string) (bool, error) {
	total, err := kv.Get(ctx, id+".total")
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	n, _, _ := strings.Cut(string(total.Value()), "|")
	want, err := strconv.Atoi(n)
	if err != nil || want <= 0 {
		return false, err
	}
	lister, err := kv.ListKeysFiltered(ctx, id+".*")
	if err != nil {
		return false, err
	}
	applied := 0
	for key := range lister.Keys() {
		if !strings.HasSuffix(key, ".total") {
			applied++
		}
	}
	return applied >= want, nil
}
