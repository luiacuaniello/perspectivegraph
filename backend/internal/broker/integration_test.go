package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
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
// dead-letters cannot be consumed by another.
func dial(t *testing.T, name string) *Broker {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	b, err := Connect(ctx, natsURL(t), "TEST_"+name, "test."+name, TLSConfig{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(b.Close)
	return b
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
		_ = b.Consume(ctx, "happy-consumer", func(_ context.Context, ev ontology.Event) error {
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
		_ = b.Consume(ctx, "retry-consumer", func(_ context.Context, ev ontology.Event) error {
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
		_ = b.Consume(ctx, "poison-consumer", func(context.Context, ontology.Event) error {
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
