package broker

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
	"github.com/nats-io/nats.go"
)

type sweepCall struct {
	tenant, source, scope string
	taken                 time.Time
	handledBefore         int64
}

// A complete snapshot is applied once, by one replica, and only after every message of
// its ingest has reached the graph. Two replicas share the consumer here, and the
// snapshot is an event too large for one message, so its chunks land on both: a sweep
// that ran on the first chunk's replica before the others landed would retract what the
// later chunks were about to assert.
func TestASnapshotIsSweptOnceAfterItsWholeBatchLanded(t *testing.T) {
	b1 := dial(t, "sweep")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b2, err := Connect(ctx, natsURL(t), "TEST_sweep", "test.sweep", Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b2.Close)

	var handled atomic.Int64
	var mu sync.Mutex
	var calls []sweepCall
	sweeper := func(_ context.Context, tenant, source, scope string, taken time.Time) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, sweepCall{tenant, source, scope, taken, handled.Load()})
		return nil
	}
	b1.WithSweeper(sweeper)
	b2.WithSweeper(sweeper)

	taken := time.Now().UTC().Truncate(time.Second)
	snap := bigEvent(12_000, 12_000)
	snap.Snapshot = &ontology.Snapshot{Scope: "cluster:prod", Taken: taken}
	partial := ontology.Event{Source: "trivy", Kind: ontology.KindFinding, Tenant: "acme",
		Nodes: []ontology.Node{{ID: "img", Label: ontology.LabelImage, Name: "app:1.0"}}}
	id, messages, err := b1.PublishBatch(ctx, []ontology.Event{snap, partial})
	if err != nil || id == "" || messages < 4 {
		t.Fatalf("batch %q in %d message(s), err %v: want a tracked batch of several", id, messages, err)
	}

	handler := func(context.Context, ontology.Event) error {
		time.Sleep(20 * time.Millisecond) // let the two replicas interleave
		handled.Add(1)
		return nil
	}
	go func() { _ = b1.Consume(ctx, handler) }()
	go func() { _ = b2.Consume(ctx, handler) }()

	deadline := time.Now().Add(45 * time.Second)
	for {
		mu.Lock()
		n := len(calls)
		mu.Unlock()
		if n > 0 && handled.Load() >= int64(messages) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %d of %d messages, %d sweep(s)", handled.Load(), messages, n)
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(time.Second) // room for a second, wrong sweep to show up
	// A message of the batch delivered again after it completed - an ack that was lost -
	// finds the batch complete too. It must not sweep a second time.
	h := nats.Header{}
	h.Set(hdrBatch, id)
	h.Set(hdrSnapshot, "1")
	b2.maybeSweep(ctx, h)
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("%d sweeps, want exactly one: %+v", len(calls), calls)
	}
	c := calls[0]
	if c.handledBefore != int64(messages) {
		t.Errorf("swept after %d of %d messages had landed", c.handledBefore, messages)
	}
	if c.tenant != "acme" || c.source != "k8s" || c.scope != "cluster:prod" || !c.taken.Equal(taken) {
		t.Errorf("swept %+v, want acme/k8s/cluster:prod taken %v - and nothing for the partial event", c, taken)
	}
}

// A pull request's event on the bus with a declaration is not swept for: the broker
// schedules sweeps by the rule the normalizer records origins by.
func TestAPullRequestsSnapshotIsNeverSwept(t *testing.T) {
	b := dial(t, "sweeppr")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var swept atomic.Int64
	b.WithSweeper(func(context.Context, string, string, string, time.Time) error { swept.Add(1); return nil })

	ev := ontology.Event{Source: "trivy", Kind: ontology.KindFinding, Tenant: "acme",
		Snapshot: &ontology.Snapshot{Scope: "image:app:1.0", Taken: time.Now()},
		Nodes: []ontology.Node{{ID: "img", Label: ontology.LabelImage, Name: "app:1.0",
			Properties: map[string]any{ontology.PropCommitSHA: "abc"}}}}
	id, _, err := b.PublishBatch(ctx, []ontology.Event{ev})
	if err != nil {
		t.Fatal(err)
	}
	var handled atomic.Int64
	go func() { _ = b.Consume(ctx, func(context.Context, ontology.Event) error { handled.Add(1); return nil }) }()
	for handled.Load() == 0 && ctx.Err() == nil {
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(time.Second)
	if st, _ := b.BatchStatus(ctx, id); !st.Complete() {
		t.Fatalf("batch not complete: %+v", st)
	}
	if swept.Load() != 0 {
		t.Fatalf("a pull request's event was swept for %d time(s)", swept.Load())
	}
}
