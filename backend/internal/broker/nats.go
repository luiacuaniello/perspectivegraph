// Package broker wraps NATS JetStream, the event bus that decouples collectors
// (producers) from the normalization layer (consumer). JetStream gives us
// at-least-once delivery and buffering so a burst of scanner output never
// overwhelms the graph core.
package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// dlqPrefix roots the dead-letter subjects. It is intentionally OUTSIDE the main
// stream's base.> filter so dead-lettered events are retained in their own stream and
// never re-consumed by the normalizer.
const dlqPrefix = "perspectivegraph.dlq"

// dlqSubjectFor scopes the dead-letter subject to one deployment's stream.
//
// It used to be a single constant while the DLQ STREAM was already named per-stream, and
// the mismatch had a sharp edge: two deployments sharing a NATS - staging and production
// on one cluster is the ordinary case - both claimed the same subject, so the second
// refused to start with "subjects overlap with an existing stream" and nothing in that
// message pointed at the cause. Found by giving each integration test its own stream.
func dlqSubjectFor(stream string) string {
	return dlqPrefix + "." + sanitizeToken(stream)
}

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

// DefaultMaxAge is how long an event may wait in the stream, and how long a
// dead-lettered one is kept, when Options.MaxAge is unset. A week matches the graph TTL
// the production values set: an event older than that would land already stale.
const DefaultMaxAge = 7 * 24 * time.Hour

// durableName is the one consumer that drains the stream. Every replica binds the same
// durable, so JetStream hands each event to exactly one of them.
const durableName = "normalizer"

// ackWait is how long JetStream waits for an ack before redelivering, and progressEvery
// how often an event still being handled asks for more time. The pair covers two
// failure modes at once: a replica that dies mid-event gets its event redelivered within
// ackWait, and a large event that legitimately takes longer than that is not redelivered
// to another replica while the first is still writing it - which used to happen past the
// 30s default and put two writers on the same nodes.
//
// Variables rather than constants so the integration test can prove the pair works
// without waiting minutes.
var (
	ackWait       = 2 * time.Minute
	progressEvery = 30 * time.Second
)

// pullBuffer caps how many events a replica holds before handling them. The handler runs
// one event at a time, and an event's ack timer starts when the server sends it, not when
// the handler reaches it: the client default of 500 left most of a backlog timing out in
// memory and being redelivered to someone else, and at up to 1 MB an event it was also
// half a gigabyte of heap.
const pullBuffer = 4

// Broker publishes and consumes ontology.Events over NATS JetStream.
type Broker struct {
	nc            *nats.Conn
	js            jetstream.JetStream
	stream        string
	streamSubject string // what the stream binds and the consumer filters (base.>)
	base          string // publish prefix: base + "." + source token
	dlq           string // dead-letter subject, scoped to this stream
	maxAge        time.Duration
	closing       atomic.Bool
}

// Connect dials NATS and ensures the durable stream and its consumer exist. The
// configured subject is treated as a base ("perspective.events"); legacy values with a
// trailing ".*" or ".>" wildcard are accepted too. The stream always binds base.> so
// every published source token matches.
// TLSConfig points at PEM files for NATS transport security (all empty → no
// app-level TLS: plain nats://, or a tls:// URL that trusts the system store, or a
// service mesh that wraps the traffic). CAFile trusts a private CA for server-auth;
// CertFile + KeyFile add a client certificate for mutual TLS.
type TLSConfig struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

// Options configures Connect. The zero value is valid: no TLS, DefaultMaxAge, and a
// connection that closes for good is only logged.
type Options struct {
	TLS TLSConfig
	// MaxAge bounds how long an event may wait in the stream, and how long a
	// dead-lettered one is kept, before JetStream discards it. <=0 means DefaultMaxAge.
	MaxAge time.Duration
	// OnClosed is called once if the connection closes for good while the broker is
	// still in use - not when Close is called. The process should stop: nothing it
	// ingests reaches the graph any more, and nothing will reconnect it.
	OnClosed func(error)
}

func Connect(ctx context.Context, url, stream, subject string, o Options) (*Broker, error) {
	b := &Broker{stream: stream, dlq: dlqSubjectFor(stream), maxAge: o.MaxAge}
	if b.maxAge <= 0 {
		b.maxAge = DefaultMaxAge
	}
	b.streamSubject, b.base = normalizeSubject(subject)

	opts := []nats.Option{
		nats.Name("perspectivegraph"),
		// Reconnect for as long as it takes. The client default gives up after 60
		// attempts - about two minutes - and then closes the connection for good: the
		// consumer stops, the process keeps serving the API, and from then on every
		// ingest is lost behind a /healthz that still says ok. A NATS pod being
		// rescheduled takes longer than that often enough to matter.
		nats.MaxReconnects(-1),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			metrics.BrokerConnected.Set(0)
			slog.Warn("broker disconnected, reconnecting", "err", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			metrics.BrokerConnected.Set(1)
			slog.Info("broker reconnected", "url", nc.ConnectedUrlRedacted())
			// The server we reconnected to may not have our stream: a NATS without a
			// persistent volume comes back empty. Without this, publishes fail with "no
			// responders" and the consumer asks a consumer that no longer exists for
			// messages, for ever. Off the callback goroutine, which serialises every
			// connection callback.
			go func() {
				ectx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := b.ensure(ectx); err != nil {
					slog.Error("broker reconnected but could not restore its stream", "err", err)
				}
			}()
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			metrics.BrokerConnected.Set(0)
			if b.closing.Load() {
				return
			}
			err := nc.LastError()
			if err == nil {
				err = errors.New("connection closed")
			}
			slog.Error("broker connection closed for good", "err", err)
			if o.OnClosed != nil {
				o.OnClosed(fmt.Errorf("nats: %w", err))
			}
		}),
	}
	if o.TLS.CAFile != "" {
		opts = append(opts, nats.RootCAs(o.TLS.CAFile))
	}
	if o.TLS.CertFile != "" && o.TLS.KeyFile != "" {
		opts = append(opts, nats.ClientCert(o.TLS.CertFile, o.TLS.KeyFile))
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	b.nc = nc
	metrics.BrokerConnected.Set(1)
	fail := func(err error) (*Broker, error) {
		b.closing.Store(true)
		nc.Close()
		return nil, err
	}
	if b.js, err = jetstream.New(nc); err != nil {
		return fail(fmt.Errorf("jetstream init: %w", err))
	}
	if err := b.ensure(ctx); err != nil {
		return fail(err)
	}

	slog.Info("broker connected", "url", nc.ConnectedUrlRedacted(), "stream", stream,
		"subject", b.streamSubject, "max_age", b.maxAge)
	return b, nil
}

// ensure creates, or brings up to date, the event stream, its dead-letter stream and the
// consumer. It is idempotent, and runs at Connect and again after every reconnect.
func (b *Broker) ensure(ctx context.Context) error {
	if err := b.ensureStream(ctx, streamConfig(b.stream, b.streamSubject, b.maxAge)); err != nil {
		return fmt.Errorf("create stream %q: %w", b.stream, err)
	}
	// Dead-letter stream: retains events that exhausted redelivery so an operator
	// (or a future replay tool) can inspect them instead of losing them silently.
	if err := b.ensureStream(ctx, dlqStreamConfig(b.stream, b.maxAge)); err != nil {
		return fmt.Errorf("create DLQ stream: %w", err)
	}
	// The consumer is created HERE, before anything can publish, not when Consume starts.
	// The stream keeps an event only while a consumer is interested in it, and one
	// published before the first consumer exists is discarded on arrival - measured on
	// NATS 2.15. On a fresh install the ingest listener can accept a scan before the
	// consumer goroutine has run.
	if _, err := b.js.CreateOrUpdateConsumer(ctx, b.stream, consumerConfig(b.streamSubject)); err != nil {
		return fmt.Errorf("create consumer %q: %w", durableName, err)
	}
	return nil
}

// ensureStream creates the stream from want, or brings an existing one's subjects,
// retention and age limit in line with it - and leaves every other setting as it finds
// it.
//
// Replacing the whole configuration, as CreateOrUpdateStream does, reset whatever the
// operator had set on the stream to its default, and the one that matters is the replica
// count. The HA recipe points the backend at a clustered NATS, and a stream forced back
// to one replica there loses its events with the node that holds them; the operator's
// `nats stream edit --replicas 3` was undone at every start, and since the stream is
// re-ensured after each reconnect, at every reconnect as well.
func (b *Broker) ensureStream(ctx context.Context, want jetstream.StreamConfig) error {
	for attempt := 0; ; attempt++ {
		s, err := b.js.Stream(ctx, want.Name)
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			_, err = b.js.CreateStream(ctx, want)
			if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) && attempt == 0 {
				continue // another replica created it first: update that one instead
			}
			return err
		}
		if err != nil {
			return err
		}
		have := s.CachedInfo().Config
		cfg := have
		cfg.Subjects = want.Subjects
		cfg.Retention = want.Retention
		cfg.MaxAge = want.MaxAge
		if cfg.Retention == have.Retention && cfg.MaxAge == have.MaxAge && slices.Equal(cfg.Subjects, have.Subjects) {
			return nil
		}
		_, err = b.js.UpdateStream(ctx, cfg)
		return err
	}
}

// streamConfig is the event stream: file-backed, drained by one durable consumer.
//
// InterestPolicy deletes an event as soon as that consumer acks (or terminates) it, so
// the stream holds the backlog and nothing else. It used to be the default LimitsPolicy
// with no limit set, which kept every event ever ingested - a scan per build and a
// connector pass every fifteen minutes, on a volume nothing ever emptied. MaxAge is the
// backstop for a backlog nobody is draining.
//
// Not WorkQueuePolicy, which reads as the obvious choice: JetStream refuses to change an
// existing stream to or from it, so every deployment upgraded from a release that
// created the stream would fail to start. Limits to Interest is an update it accepts.
func streamConfig(stream, subject string, maxAge time.Duration) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:      stream,
		Subjects:  []string{subject},
		Storage:   jetstream.FileStorage,
		Retention: jetstream.InterestPolicy,
		MaxAge:    maxAge,
	}
}

// dlqStreamConfig keeps dead-lettered events for MaxAge. Nothing consumes this stream,
// so it keeps the default LimitsPolicy: under InterestPolicy it would keep nothing.
func dlqStreamConfig(stream string, maxAge time.Duration) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:     stream + "_DLQ",
		Subjects: []string{dlqSubjectFor(stream)},
		Storage:  jetstream.FileStorage,
		MaxAge:   maxAge,
	}
}

func consumerConfig(filter string) jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Durable:       durableName,
		FilterSubject: filter,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       ackWait,
		MaxDeliver:    maxDeliver,
	}
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

// Consume invokes handler for every event on the durable consumer Connect created.
// Failing events are redelivered with backoff up to maxDeliver times, then terminated.
//
// It blocks until ctx is cancelled, and returns an error if the consumer stops on its
// own first - the connection closed, or someone deleted the consumer. That used to go
// unnoticed: Consume sat on ctx while nothing arrived, so the process looked healthy and
// ingested nothing.
func (b *Broker) Consume(ctx context.Context, handler func(context.Context, ontology.Event) error) error {
	cons, err := b.js.Consumer(ctx, b.stream, durableName)
	if err != nil {
		return fmt.Errorf("consumer %q: %w", durableName, err)
	}

	cc, err := cons.Consume(func(msg jetstream.Msg) {
		var ev ontology.Event
		if err := json.Unmarshal(msg.Data(), &ev); err != nil {
			slog.Error("drop malformed event", "err", err)
			metrics.NormalizeEvents.WithLabelValues("error").Inc()
			b.deadLetter(ctx, msg.Data())
			_ = msg.Term() // poison message - do not redeliver
			return
		}
		stop := keepInProgress(msg, progressEvery)
		err := handler(ctx, ev)
		stop()
		if err != nil {
			metrics.NormalizeEvents.WithLabelValues("error").Inc()
			attempt := uint64(1)
			if meta, merr := msg.Metadata(); merr == nil {
				attempt = meta.NumDelivered
			}
			delay, giveUp := retryOrDeadLetter(attempt)
			if giveUp {
				slog.Error("handler failed, giving up after max deliveries - dead-lettering",
					"source", ev.Source, "attempts", attempt, "err", err)
				b.deadLetter(ctx, msg.Data())
				_ = msg.Term()
				return
			}
			slog.Warn("handler failed, will redeliver",
				"source", ev.Source, "attempt", attempt, "retry_in", delay, "err", err)
			_ = msg.NakWithDelay(delay)
			return
		}
		metrics.NormalizeEvents.WithLabelValues("ok").Inc()
		_ = msg.Ack()
	},
		jetstream.PullMaxMessages(pullBuffer),
		jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
			slog.Warn("broker consumer error", "err", err)
		}),
	)
	if err != nil {
		return fmt.Errorf("start consume: %w", err)
	}
	defer cc.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cc.Closed():
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("broker consumer stopped: the connection closed or the consumer was deleted")
	}
}

// keepInProgress tells JetStream, every `every`, that msg is still being worked on, so
// its ack timer restarts instead of expiring into a redelivery. The returned func stops
// it and must be called before the message is acked.
func keepInProgress(msg jetstream.Msg, every time.Duration) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				_ = msg.InProgress()
			}
		}
	}()
	return func() { close(done) }
}

// Close drains and closes the underlying connection. OnClosed is not called for it.
func (b *Broker) Close() {
	if b.nc != nil {
		b.closing.Store(true)
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
	if _, err := b.js.Publish(context.WithoutCancel(ctx), b.dlq, data); err != nil {
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

// retryOrDeadLetter decides what a failed delivery has earned: another attempt after a
// backoff, or the dead-letter queue.
//
// It is a function rather than three lines inside the consume callback because the
// boundary is the whole point and it is off-by-one country. Give up one delivery too
// early and an event that would have succeeded on its last retry is dead-lettered - a
// node missing from the graph, so an attack path that never appears. Give up one too
// late and a permanently failing event is redelivered for ever, and the backlog behind
// it never drains. `attempt` is 1-based: it is NumDelivered, which is 1 on the first
// delivery, so the cap is reached when attempt EQUALS maxDeliver.
func retryOrDeadLetter(attempt uint64) (delay time.Duration, giveUp bool) {
	if attempt >= maxDeliver {
		return 0, true
	}
	return backoffFor(attempt), false
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
