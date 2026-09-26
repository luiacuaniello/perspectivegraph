package connector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// fakeConn is a connector that returns a fixed result (events or an error).
type fakeConn struct {
	src    string
	events []ontology.Event
	err    error
	calls  int
}

func (c *fakeConn) Source() string { return c.src }
func (c *fakeConn) Collect(context.Context) ([]ontology.Event, error) {
	c.calls++
	return c.events, c.err
}

// capturePub records everything published.
type capturePub struct {
	mu        sync.Mutex
	published []ontology.Event
}

func (p *capturePub) Publish(_ context.Context, ev ontology.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.published = append(p.published, ev)
	return nil
}

func ev(nodeID string) ontology.Event {
	return ontology.Event{Source: "cloudnet", Nodes: []ontology.Node{{ID: nodeID, Label: ontology.LabelLoadBalancer, Name: nodeID}}}
}

func TestSchedulerCollectsAndStampsTenant(t *testing.T) {
	pub := &capturePub{}
	c := &fakeConn{src: "aws", events: []ontology.Event{ev("a"), ev("b")}}
	s := NewScheduler(pub, 0, c).WithTenant("acme")

	s.collectAll(context.Background())

	if len(pub.published) != 2 {
		t.Fatalf("published = %d, want 2", len(pub.published))
	}
	for _, e := range pub.published {
		if e.Tenant != "acme" {
			t.Errorf("event not routed to tenant: %q", e.Tenant)
		}
	}
	st := statusOf(s, "aws")
	if !st.LastOK || st.EventsLastRun != 2 || st.Runs != 1 {
		t.Errorf("status = %+v, want ok/2/1", st)
	}
}

// TestErrorIsolation: one connector failing must not stop the others.
func TestErrorIsolation(t *testing.T) {
	pub := &capturePub{}
	bad := &fakeConn{src: "aws", err: errors.New("boom")}
	good := &fakeConn{src: "github", events: []ontology.Event{ev("g")}}
	s := NewScheduler(pub, 0, bad, good)

	s.collectAll(context.Background())

	if len(pub.published) != 1 || pub.published[0].Nodes[0].ID != "g" {
		t.Fatalf("the healthy connector should still publish; got %d events", len(pub.published))
	}
	if st := statusOf(s, "aws"); st.LastOK || st.LastError == "" {
		t.Errorf("failed connector status should record the error: %+v", st)
	}
	if st := statusOf(s, "github"); !st.LastOK {
		t.Errorf("healthy connector status should be ok: %+v", st)
	}
}

// TestLeaderGating: a non-leader replica must not pull at all.
func TestLeaderGating(t *testing.T) {
	pub := &capturePub{}
	c := &fakeConn{src: "aws", events: []ontology.Event{ev("a")}}
	s := NewScheduler(pub, 0, c).WithLeader(notLeader{})

	s.collectAll(context.Background())

	if c.calls != 0 {
		t.Errorf("non-leader must not invoke Collect, got %d calls", c.calls)
	}
	if len(pub.published) != 0 {
		t.Errorf("non-leader must not publish, got %d", len(pub.published))
	}
}

type notLeader struct{}

func (notLeader) IsLeader(context.Context) bool { return false }

// blockingConn hangs until its context is cancelled - a stand-in for a stalled
// external API.
type blockingConn struct{ src string }

func (c *blockingConn) Source() string { return c.src }
func (c *blockingConn) Collect(ctx context.Context) ([]ontology.Event, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestCollectTimeout: a hung connector is bounded by WithTimeout and recorded as
// degraded, instead of blocking the loop forever.
func TestCollectTimeout(t *testing.T) {
	pub := &capturePub{}
	s := NewScheduler(pub, 0, &blockingConn{src: "aws"}).WithTimeout(50 * time.Millisecond)

	start := time.Now()
	s.collectAll(context.Background())
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("collect not bounded by timeout: took %v", elapsed)
	}
	if st := statusOf(s, "aws"); st.LastOK {
		t.Error("a timed-out collect should be recorded as degraded")
	}
}

func statusOf(s *Scheduler, src string) Status {
	for _, st := range s.Status() {
		if st.Source == src {
			return st
		}
	}
	return Status{}
}

// batchPub publishes a whole collection as one tracked batch, as the broker does.
type batchPub struct {
	capturePub
	batches int
}

func (p *batchPub) PublishBatch(_ context.Context, events []ontology.Event) (string, int, error) {
	p.batches++
	p.published = append(p.published, events...)
	return "0123456789abcdef0123456789abcdef", len(events), nil
}

// A collection is published as one batch, so the complete snapshots in it are applied
// once all of it has landed - stamped with the time the connector took them. Published
// untracked, the declaration is dropped: nothing could say when the whole had arrived.
func TestACollectionIsOneBatchAndItsSnapshotsAreTakenNow(t *testing.T) {
	snap := ev("a")
	snap.Snapshot = &ontology.Snapshot{Scope: "aws:111111111111/eu-west-1"}
	before := time.Now().UTC()

	pub := &batchPub{}
	NewScheduler(pub, 0, &fakeConn{src: "aws", events: []ontology.Event{snap, ev("b")}}).collectAll(context.Background())
	if pub.batches != 1 || len(pub.published) != 2 {
		t.Fatalf("%d batch(es), %d event(s): want the collection as one batch", pub.batches, len(pub.published))
	}
	if sn := pub.published[0].Snapshot; sn == nil || sn.Taken.Before(before) {
		t.Fatalf("snapshot %+v: want it taken at collection time", sn)
	}
	if pub.published[1].Snapshot != nil {
		t.Error("a partial event came out declared complete")
	}

	plain := &capturePub{}
	NewScheduler(plain, 0, &fakeConn{src: "aws", events: []ontology.Event{snap}}).collectAll(context.Background())
	if plain.published[0].Snapshot != nil {
		t.Error("an untracked publish kept a snapshot declaration nothing can apply")
	}
}
