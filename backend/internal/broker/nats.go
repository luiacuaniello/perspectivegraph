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
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// dlqSubject is the dead-letter subject. It is intentionally OUTSIDE the main
// stream's base.> filter so dead-lettered events are retained in their own
// stream and never re-consumed by the normalizer.
const dlqSubject = "perspectivegraph.dlq"

// maxDeliver caps redeliveries of a failing event. Edge upserts fail (and Nak)
// until their endpoint nodes arrive, which normally resolves within a couple
// of passes - an event still failing after this many attempts is poison and is
// terminated instead of looping forever.
const maxDeliver = 8

// redeliveryBackoff spaces out retries of a failing event; attempts beyond the
// list reuse the last delay.
var redeliveryBackoff = []time.Duration{
	time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute,
}

// Broker publishes and consumes ontology.Events over NATS JetStream.
type Broker struct {
	nc            *nats.Conn
	js            jetstream.JetStream
	stream        string
	streamSubject string // what the stream binds and the consumer filters (base.>)
	base          string // publish prefix: base + "." + source token
}

// Connect dials NATS and ensures the durable stream exists. The configured
// subject is treated as a base ("perspective.events"); legacy values with a
// trailing ".*" or ".>" wildcard are accepted too. The stream always binds
// base.> so every published source token matches.
// TLSConfig points at PEM files for NATS transport security (all empty → no
// app-level TLS: plain nats://, or a tls:// URL that trusts the system store, or a
// service mesh that wraps the traffic). CAFile trusts a private CA for server-auth;
// CertFile + KeyFile add a client certificate for mutual TLS.
type TLSConfig struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

func Connect(ctx context.Context, url, stream, subject string, tlsConf TLSConfig) (*Broker, error) {
	opts := []nats.Option{nats.Name("perspectivegraph")}
	if tlsConf.CAFile != "" {
		opts = append(opts, nats.RootCAs(tlsConf.CAFile))
	}
	if tlsConf.CertFile != "" && tlsConf.KeyFile != "" {
		opts = append(opts, nats.ClientCert(tlsConf.CertFile, tlsConf.KeyFile))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	streamSubject, base := normalizeSubject(subject)
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     stream,
		Subjects: []string{streamSubject},
		Storage:  jetstream.FileStorage,
	}); err != nil {
		nc.Close()
		return nil, fmt.Errorf("create stream %q: %w", stream, err)
	}
	// Dead-letter stream: retains events that exhausted redelivery so an operator
	// (or a future replay tool) can inspect them instead of losing them silently.
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     stream + "_DLQ",
		Subjects: []string{dlqSubject},
		Storage:  jetstream.FileStorage,
	}); err != nil {
		nc.Close()
		return nil, fmt.Errorf("create DLQ stream: %w", err)
	}

	slog.Info("broker connected", "url", url, "stream", stream, "subject", streamSubject)
	return &Broker{nc: nc, js: js, stream: stream, streamSubject: streamSubject, base: base}, nil
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
// event. Failing events are redelivered with backoff up to maxDeliver times,
// then terminated. It blocks until ctx is cancelled.
func (b *Broker) Consume(ctx context.Context, durable string, handler func(context.Context, ontology.Event) error) error {
	cons, err := b.js.CreateOrUpdateConsumer(ctx, b.stream, jetstream.ConsumerConfig{
		Durable:       durable,
		FilterSubject: b.streamSubject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    maxDeliver,
	})
	if err != nil {
		return fmt.Errorf("create consumer %q: %w", durable, err)
	}

	cc, err := cons.Consume(func(msg jetstream.Msg) {
		var ev ontology.Event
		if err := json.Unmarshal(msg.Data(), &ev); err != nil {
			slog.Error("drop malformed event", "err", err)
			b.deadLetter(ctx, msg.Data())
			_ = msg.Term() // poison message - do not redeliver
			return
		}
		if err := handler(ctx, ev); err != nil {
			attempt := uint64(1)
			if meta, merr := msg.Metadata(); merr == nil {
				attempt = meta.NumDelivered
			}
			if attempt >= maxDeliver {
				slog.Error("handler failed, giving up after max deliveries - dead-lettering",
					"source", ev.Source, "attempts", attempt, "err", err)
				b.deadLetter(ctx, msg.Data())
				_ = msg.Term()
				return
			}
			delay := backoffFor(attempt)
			slog.Warn("handler failed, will redeliver",
				"source", ev.Source, "attempt", attempt, "retry_in", delay, "err", err)
			_ = msg.NakWithDelay(delay)
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
	return b.base + "." + sanitizeToken(source)
}

// deadLetter retains an undeliverable event in the DLQ stream and counts it.
// Best-effort: a failed DLQ publish is logged, never blocks Term.
func (b *Broker) deadLetter(ctx context.Context, data []byte) {
	metrics.BrokerDeadLettered.Inc()
	if _, err := b.js.Publish(context.WithoutCancel(ctx), dlqSubject, data); err != nil {
		slog.Warn("dead-letter publish failed", "err", err)
	}
}

// normalizeSubject turns the configured subject into the stream binding and
// the publish base. "perspective.events", "perspective.events.*" and
// "perspective.events.>" all yield ("perspective.events.>", "perspective.events").
func normalizeSubject(configured string) (streamSubject, base string) {
	base = strings.TrimSpace(configured)
	base = strings.TrimSuffix(base, ".>")
	base = strings.TrimSuffix(base, ".*")
	base = strings.TrimSuffix(base, ".")
	if base == "" {
		base = "perspective.events"
	}
	return base + ".>", base
}

// sanitizeToken makes an event source safe to embed as a single NATS subject
// token: anything outside [A-Za-z0-9_-] (dots, spaces, wildcards, …) becomes
// '-', and an empty source becomes "unknown".
func sanitizeToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			sb.WriteRune(r)
		default:
			sb.WriteRune('-')
		}
	}
	return sb.String()
}

// backoffFor returns the redelivery delay after the given (1-based) attempt.
func backoffFor(attempt uint64) time.Duration {
	i := int(attempt) - 1 // #nosec G115 -- redelivery attempt is small, bounded by MaxDeliver
	if i < 0 {
		i = 0
	}
	if i >= len(redeliveryBackoff) {
		i = len(redeliveryBackoff) - 1
	}
	return redeliveryBackoff[i]
}
