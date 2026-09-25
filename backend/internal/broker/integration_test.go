package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// The delivery guarantees, against a real JetStream rather than a mock.
//
// The unit tests above cover the redelivery POLICY; these cover the wiring that applies
// it, which is where the guarantee actually lives: a mock that returns whatever the test
// wants proves nothing about whether an Ack was sent, whether Term removed the message,
// or whether a Nak really came back later. Every one of those failures is silent - the
// event simply never becomes a node, so an attack path never appears - which is exactly
// the class this engine must not have.
//
// Skipped when there is no NATS to talk to, the same way the AGE contract test skips
// without Postgres. CI runs it with the same pinned image the chart deploys.

func natsURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("PERSPECTIVE_TEST_NATS_URL")
	if url == "" {
		url = "nats://localhost:4222"
	}
	host := url
	for _, p := range []string{"nats://", "tls://"} {
		if len(host) > len(p) && host[:len(p)] == p {
			host = host[len(p):]
		}
	}
	conn, err := net.DialTimeout("tcp", host, 500*time.Millisecond)
	if err != nil {
		t.Skipf("no NATS at %s (%v) - run one with `docker run -p 4222:4222 nats -js`", url, err)
	}
	_ = conn.Close()
	return url
}

// dial gives each test its own stream and subject tree, so a message one test
// dead-letters cannot be consumed by another - and starts it empty, so nothing an
// earlier run left behind is delivered to this one.
func dial(t *testing.T, name string) *Broker {
	t.Helper()
	return dialWith(t, name, Options{})
}

func dialWith(t *testing.T, name string, o Options) *Broker {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	url := natsURL(t)
	dropStreams(t, url, "TEST_"+name)
	b, err := Connect(ctx, url, "TEST_"+name, "test."+name, o)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(b.Close)
	return b
}

// dropStreams deletes a test's stream and its DLQ, if an earlier run left them.
func dropStreams(t *testing.T, url, stream string) {
	t.Helper()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range []string{stream, stream + "_DLQ"} {
		if err := js.DeleteStream(ctx, s); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
			t.Fatalf("delete stream %s: %v", s, err)
		}
	}
}

func event(source, id string) ontology.Event {
	return ontology.Event{
		Source:     source,
		Kind:       ontology.KindAsset,
		ObservedAt: time.Now().UTC(),
		Nodes:      []ontology.Node{{ID: id, Label: ontology.LabelContainer, Name: id}},
	}
}

// The happy path: what is published is what the handler receives, intact.
func TestPublishedEventReachesTheHandler(t *testing.T) {
	b := dial(t, "happy")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	got := make(chan ontology.Event, 1)
	go func() {
		_ = b.Consume(ctx, func(_ context.Context, ev ontology.Event) error {
			select {
			case got <- ev:
			default:
			}
			return nil
		})
	}()
	time.Sleep(500 * time.Millisecond) // let the consumer bind before publishing

	if err := b.Publish(ctx, event("trivy", "node-1")); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case ev := <-got:
		if ev.Source != "trivy" || len(ev.Nodes) != 1 || ev.Nodes[0].ID != "node-1" {
			t.Fatalf("event arrived altered: %+v", ev)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the event never reached the handler")
	}
}

// A handler that fails must see the message again - otherwise a transient database blip
// silently drops whatever was in flight, and the graph is quietly short a node.
func TestFailedHandlerSeesTheEventAgain(t *testing.T) {
	b := dial(t, "retry")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var deliveries atomic.Int64
	done := make(chan struct{})
	var once bool
	go func() {
		_ = b.Consume(ctx, func(_ context.Context, ev ontology.Event) error {
			n := deliveries.Add(1)
			if n < 2 {
				return errors.New("transient failure")
			}
			if !once {
				once = true
				close(done)
			}
			return nil
		})
	}()
	time.Sleep(500 * time.Millisecond)

	if err := b.Publish(ctx, event("semgrep", "node-retry")); err != nil {
		t.Fatalf("publish: %v", err)
	}

	select {
	case <-done:
		if got := deliveries.Load(); got < 2 {
			t.Fatalf("handler saw the event %d time(s); a failure must earn a redelivery", got)
		}
	case <-time.After(25 * time.Second):
		t.Fatalf("the event was never redelivered after a failure (deliveries=%d)", deliveries.Load())
	}
}

// A message that cannot be decoded must be terminated, not redelivered: it will never
// parse, so retrying it for ever holds up everything behind it. It goes to the DLQ so
// the operator can still see what arrived.
func TestMalformedMessageIsTerminatedNotRedelivered(t *testing.T) {
	b := dial(t, "poison")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var calls atomic.Int64
	go func() {
		_ = b.Consume(ctx, func(context.Context, ontology.Event) error {
			calls.Add(1)
			return nil
		})
	}()
	time.Sleep(500 * time.Millisecond)

	// Straight onto the subject, bypassing Publish, so it is genuinely undecodable.
	if _, err := b.js.Publish(ctx, b.subjectFor("trivy"), []byte("{not json")); err != nil {
		t.Fatalf("publish raw: %v", err)
	}
	time.Sleep(4 * time.Second)

	if got := calls.Load(); got != 0 {
		t.Errorf("the handler was called %d time(s) with an undecodable message", got)
	}
	msgs, err := countDLQ(ctx, b)
	if err != nil {
		t.Fatalf("read dlq: %v", err)
	}
	if msgs == 0 {
		t.Error("the poison message was dropped without reaching the dead-letter queue")
	}
}

// countDLQ reports how many messages the dead-letter stream holds.
func countDLQ(ctx context.Context, b *Broker) (uint64, error) {
	s, err := b.js.Stream(ctx, b.stream+"_DLQ")
	if err != nil {
		return 0, fmt.Errorf("dlq stream %s_DLQ: %w", b.stream, err)
	}
	info, err := s.Info(ctx)
	if err != nil {
		return 0, err
	}
	return info.State.Msgs, nil
}

// streamMsgs reports how many messages the event stream holds.
func streamMsgs(ctx context.Context, b *Broker) (uint64, error) {
	s, err := b.js.Stream(ctx, b.stream)
	if err != nil {
		return 0, err
	}
	info, err := s.Info(ctx)
	if err != nil {
		return 0, err
	}
	return info.State.Msgs, nil
}

// An event that has been handled must leave the stream. The stream used to keep every
// event ever ingested, on a volume nothing emptied; now it holds the backlog only.
func TestAckedEventLeavesTheStream(t *testing.T) {
	b := dial(t, "retention")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	handled := make(chan struct{}, 1)
	go func() {
		_ = b.Consume(ctx, func(context.Context, ontology.Event) error {
			select {
			case handled <- struct{}{}:
			default:
			}
			return nil
		})
	}()
	if err := b.Publish(ctx, event("trivy", "node-kept")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case <-handled:
	case <-time.After(15 * time.Second):
		t.Fatal("the event never reached the handler")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		n, err := streamMsgs(ctx, b)
		if err != nil {
			t.Fatalf("stream info: %v", err)
		}
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the stream still holds %d message(s) after the event was acked", n)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Under interest retention a stream discards what is published while no consumer
// exists. Connect creates the consumer, so an event that arrives before Consume has
// started - a scan accepted in the first second of a fresh install - is still there
// when it does.
func TestEventPublishedBeforeConsumeIsKept(t *testing.T) {
	b := dial(t, "early")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := b.Publish(ctx, event("trivy", "node-early")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if n, err := streamMsgs(ctx, b); err != nil || n != 1 {
		t.Fatalf("stream holds %d message(s) (err %v) before any consumer ran; want 1", n, err)
	}

	got := make(chan string, 1)
	go func() {
		_ = b.Consume(ctx, func(_ context.Context, ev ontology.Event) error {
			select {
			case got <- ev.Nodes[0].ID:
			default:
			}
			return nil
		})
	}()
	select {
	case id := <-got:
		if id != "node-early" {
			t.Fatalf("got %q, want node-early", id)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("an event published before Consume started never reached the handler")
	}
}

// A stream created by an earlier release - limits retention, no age limit - must be
// updated in place, not refused. JetStream refuses to move a stream to or from
// work-queue retention, which is why it is not used: every upgraded install would fail
// to start.
func TestStreamFromAnEarlierReleaseIsUpgradedInPlace(t *testing.T) {
	url := natsURL(t)
	const name = "upgrade"
	dropStreams(t, url, "TEST_"+name)

	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()
	js, _ := jetstream.New(nc)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: "TEST_" + name, Subjects: []string{"test." + name + ".>"}, Storage: jetstream.FileStorage,
	}); err != nil {
		t.Fatalf("create the old stream: %v", err)
	}

	b, err := Connect(ctx, url, "TEST_"+name, "test."+name, Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("connect over a stream an earlier release created: %v", err)
	}
	defer b.Close()
	s, err := js.Stream(ctx, "TEST_"+name)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	info, err := s.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info.Config.Retention != jetstream.InterestPolicy || info.Config.MaxAge != time.Hour {
		t.Fatalf("stream is %s retention with max age %v; want interest, 1h", info.Config.Retention, info.Config.MaxAge)
	}
}

// A handler that takes longer than the ack wait must not see its event handed to
// someone else meanwhile. It did, past the 30s default: two replicas writing the same
// nodes at once.
func TestSlowHandlerIsNotRedelivered(t *testing.T) {
	oldWait, oldEvery := ackWait, progressEvery
	ackWait, progressEvery = 2*time.Second, 500*time.Millisecond
	t.Cleanup(func() { ackWait, progressEvery = oldWait, oldEvery })

	b := dial(t, "slow")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var deliveries atomic.Int64
	go func() {
		_ = b.Consume(ctx, func(context.Context, ontology.Event) error {
			deliveries.Add(1)
			time.Sleep(3 * ackWait)
			return nil
		})
	}()
	if err := b.Publish(ctx, event("trivy", "node-slow")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	time.Sleep(4*ackWait + time.Second)
	if got := deliveries.Load(); got != 1 {
		t.Fatalf("a handler three ack-waits long saw its event %d times; want 1", got)
	}
}

// A consumer that stops on its own must make Consume return, not leave it waiting on a
// context that will never end while nothing arrives.
func TestConsumeReturnsWhenTheConsumerIsDeleted(t *testing.T) {
	b := dial(t, "deleted")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- b.Consume(ctx, func(context.Context, ontology.Event) error { return nil }) }()
	time.Sleep(500 * time.Millisecond)
	if err := b.js.DeleteConsumer(ctx, b.stream, durableName); err != nil {
		t.Fatalf("delete consumer: %v", err)
	}
	select {
	case err := <-done:
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Consume returned %v; want an error saying the consumer stopped", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Consume kept waiting after its consumer was deleted")
	}
}

// OnClosed fires when the connection goes away for good behind the broker's back, and
// not when the broker is closed on purpose at shutdown.
func TestOnClosedFiresOnlyForAnUnplannedClose(t *testing.T) {
	var calls atomic.Int64
	onClosed := func(error) { calls.Add(1) }

	planned := dialWith(t, "planned-close", Options{OnClosed: onClosed})
	planned.Close()
	time.Sleep(500 * time.Millisecond)
	if got := calls.Load(); got != 0 {
		t.Fatalf("OnClosed ran %d time(s) for a Close the process asked for", got)
	}

	unplanned := dialWith(t, "unplanned-close", Options{OnClosed: onClosed})
	unplanned.nc.Close() // what the client does once it stops reconnecting
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("OnClosed ran %d time(s) when the connection closed unasked; want 1", got)
	}
}

// Every handled delivery is counted by result. The counter used to be registered and
// never incremented, so the alert on ingest errors could not fire.
func TestHandledEventsAreCounted(t *testing.T) {
	b := dial(t, "counted")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ok0 := normalized(t, "ok")
	errs0 := normalized(t, "error")
	var calls atomic.Int64
	go func() {
		_ = b.Consume(ctx, func(context.Context, ontology.Event) error {
			if calls.Add(1) == 1 {
				return errors.New("transient")
			}
			return nil
		})
	}()
	if err := b.Publish(ctx, event("trivy", "node-counted")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for normalized(t, "ok") == ok0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if d := normalized(t, "ok") - ok0; d != 1 {
		t.Errorf("ok count moved by %v; want 1", d)
	}
	if d := normalized(t, "error") - errs0; d != 1 {
		t.Errorf("error count moved by %v; want 1 for the failed first attempt", d)
	}
}

// normalized reads perspectivegraph_normalize_events_total{result} the way a scraper
// would, from the exposition the /metrics handler serves.
func normalized(t *testing.T, result string) float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	prefix := `perspectivegraph_normalize_events_total{result="` + result + `"} `
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if v, ok := strings.CutPrefix(line, prefix); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return f
		}
	}
	t.Fatalf("no %s series in the exposition", prefix)
	return 0
}

// Settings the operator put on the stream are theirs. The replica count is the one that
// matters - a clustered NATS is the HA recipe, and a stream forced back to one replica
// loses its events with the node that holds them - but a single-node test server cannot
// hold three replicas, so this checks two others the same way: a byte cap and a
// description, which a full replacement of the configuration used to wipe.
func TestConnectKeepsTheOperatorsStreamSettings(t *testing.T) {
	url := natsURL(t)
	const name = "operator"
	dropStreams(t, url, "TEST_"+name)

	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()
	js, _ := jetstream.New(nc)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{
		Name: "TEST_" + name, Subjects: []string{"test." + name + ".>"}, Storage: jetstream.FileStorage,
		MaxBytes: 64 << 20, Description: "sized by the platform team",
	}); err != nil {
		t.Fatalf("create the operator's stream: %v", err)
	}

	b, err := Connect(ctx, url, "TEST_"+name, "test."+name, Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer b.Close()
	s, err := js.Stream(ctx, "TEST_"+name)
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.CachedInfo().Config
	if cfg.MaxBytes != 64<<20 || cfg.Description != "sized by the platform team" {
		t.Errorf("the operator's settings were reset: max bytes %d, description %q", cfg.MaxBytes, cfg.Description)
	}
	if cfg.Retention != jetstream.InterestPolicy || cfg.MaxAge != time.Hour {
		t.Errorf("the backend's own settings did not apply: retention %s, max age %v", cfg.Retention, cfg.MaxAge)
	}
}

// An event larger than the server's message limit used to be refused at the door - a
// large cluster or account never reached the graph. It is split, every chunk is
// delivered, and the batch reports complete only once the last one has been applied.
func TestAnEventLargerThanAMessageArrivesWholeAndItsBatchCompletes(t *testing.T) {
	b := dial(t, "large")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ev := bigEvent(12_000, 12_000) // ~3 MB of JSON, three times the default max_payload
	id, messages, err := b.PublishBatch(ctx, []ontology.Event{ev})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if id == "" || messages < 3 {
		t.Fatalf("batch %q in %d message(s); want a tracked batch of several", id, messages)
	}
	if st, err := b.BatchStatus(ctx, id); err != nil || st.Complete() || st.Messages != messages || st.Tenant != "acme" {
		t.Fatalf("before any consumer ran: %+v (err %v); want %d messages, none applied", st, err, messages)
	}

	var gotNodes, gotEdges atomic.Int64
	go func() {
		_ = b.Consume(ctx, func(_ context.Context, ev ontology.Event) error {
			gotNodes.Add(int64(len(ev.Nodes)))
			gotEdges.Add(int64(len(ev.Edges)))
			return nil
		})
	}()
	deadline := time.Now().Add(45 * time.Second)
	for {
		st, err := b.BatchStatus(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Complete() {
			if st.AppliedAt.IsZero() {
				t.Error("a complete batch has no applied time")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("batch never completed: %+v", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if gotNodes.Load() != 12_000 || gotEdges.Load() != 12_000 {
		t.Errorf("handler saw %d nodes and %d edges, want 12000 and 12000", gotNodes.Load(), gotEdges.Load())
	}
}
