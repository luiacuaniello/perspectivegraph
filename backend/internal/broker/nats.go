// Package broker wraps NATS JetStream, the event bus that decouples collectors
// (producers) from the normalization layer (consumer). JetStream gives us
// at-least-once delivery and buffering so a burst of scanner output never
// overwhelms the graph core.
package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aegisgraph/aegisgraph/pkg/ontology"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Broker publishes and consumes ontology.Events over NATS JetStream.
type Broker struct {
	nc      *nats.Conn
	js      jetstream.JetStream
	stream  string
	subject string
}

// Connect dials NATS and ensures the durable stream exists.
func Connect(ctx context.Context, url, stream, subject string) (*Broker, error) {
	nc, err := nats.Connect(url, nats.Name("aegisgraph"))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     stream,
		Subjects: []string{subject},
		Storage:  jetstream.FileStorage,
	}); err != nil {
		nc.Close()
		return nil, fmt.Errorf("create stream %q: %w", stream, err)
	}

	slog.Info("broker connected", "url", url, "stream", stream, "subject", subject)
	return &Broker{nc: nc, js: js, stream: stream, subject: subject}, nil
}

// Publish serializes an event and pushes it onto the bus. The subject is
// suffixed with the event source so consumers can filter by collector.
func (b *Broker) Publish(ctx context.Context, ev ontology.Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	subject := b.subjectFor(ev.Source)
	if _, err := b.js.Publish(ctx, subject, data); err != nil {
		return fmt.Errorf("publish %q: %w", subject, err)
	}
	return nil
}

// Consume registers a durable push consumer and invokes handler for every
// event. It blocks until ctx is cancelled.
func (b *Broker) Consume(ctx context.Context, durable string, handler func(context.Context, ontology.Event) error) error {
	cons, err := b.js.CreateOrUpdateConsumer(ctx, b.stream, jetstream.ConsumerConfig{
		Durable:       durable,
		FilterSubject: b.subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer %q: %w", durable, err)
	}

	cc, err := cons.Consume(func(msg jetstream.Msg) {
		var ev ontology.Event
		if err := json.Unmarshal(msg.Data(), &ev); err != nil {
			slog.Error("drop malformed event", "err", err)
			_ = msg.Term() // poison message — do not redeliver
			return
		}
		if err := handler(ctx, ev); err != nil {
			slog.Error("handler failed, will redeliver", "source", ev.Source, "err", err)
			_ = msg.Nak()
			return
		}
		_ = msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("start consume: %w", err)
	}
	defer cc.Stop()

	<-ctx.Done()
	return ctx.Err()
}

// Close drains and closes the underlying connection.
func (b *Broker) Close() {
	if b.nc != nil {
		_ = b.nc.Drain()
	}
}

func (b *Broker) subjectFor(source string) string {
	// "aegis.events.*" -> "aegis.events.trivy"
	base := b.subject
	if len(base) > 0 && base[len(base)-1] == '*' {
		base = base[:len(base)-1]
	}
	if source == "" {
		source = "unknown"
	}
	return base + source
}
