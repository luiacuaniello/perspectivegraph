package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Large events, and knowing when all of one has landed.
//
// A NATS message is capped by the server's max_payload - 1 MiB by default - and one
// event was one message. The Kubernetes and IAM collectors put a whole cluster or account
// in one event, so a large estate was refused at ingest with a 502 and never reached the
// graph at all; genload split its events for exactly this reason, and nothing else did.
// Every event over the limit is now split into chunks, nodes first, each a valid event
// carrying the original's source, kind, time and tenant.
//
// Splitting has a price the merge gate would pay: an ingest can now be several messages,
// consumed by several replicas, and an analyzer pass can run between them - over half a
// report, whose verdict may be clean because the half that makes it red has not landed.
// So an ingest is a batch: its messages carry the batch id, each consumer records the one
// it applied in a key-value bucket every replica shares, and BatchStatus says when the
// last one landed. The gate waits for that before it trusts a verdict.

// ErrTooLarge is returned for an event holding one node or edge that does not fit in a
// message on its own. Nothing can split it further. It reports TooLarge, which the ingest
// door answers with 413 rather than 502 - without the bus importing the HTTP layer.
var ErrTooLarge error = tooLargeError{}

type tooLargeError struct{}

func (tooLargeError) Error() string {
	return "a single node or edge is larger than the event bus accepts in one message"
}
func (tooLargeError) TooLarge() bool { return true }

// Message headers of a batched publish.
const (
	hdrBatch = "Pg-Batch"
	hdrSeq   = "Pg-Batch-Seq"
	hdrTotal = "Pg-Batch-Total"
)

// batchTTL is how long the bucket remembers a batch - far longer than a gate waits.
const batchTTL = time.Hour

// headerRoom is what a message keeps free under max_payload for its headers.
const headerRoom = 1024

var batchIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// BatchStatus is how much of one ingest has been applied to the graph.
type BatchStatus struct {
	ID       string
	Tenant   string
	Messages int
	Applied  int
	// AppliedAt is when the last message was applied - set only once all of them were.
	AppliedAt time.Time
}

// Complete reports whether every message of the batch has been applied.
func (s BatchStatus) Complete() bool { return s.Messages > 0 && s.Applied >= s.Messages }

// messageLimit is the largest event body one message may carry on this connection.
func (b *Broker) messageLimit() int {
	return int(b.nc.MaxPayload()) - headerRoom
}

// PublishBatch publishes an ingest's events as one batch, splitting any that exceed the
// message limit, and returns the batch id and how many messages it took. The id is empty
// when the batch cannot be tracked - the events are still published.
func (b *Broker) PublishBatch(ctx context.Context, events []ontology.Event) (string, int, error) {
	var bodies [][]byte
	var subjects []string
	for _, ev := range events {
		chunks, err := splitEvent(ev, b.messageLimit())
		if err != nil {
			return "", 0, err
		}
		for _, c := range chunks {
			bodies = append(bodies, c)
			subjects = append(subjects, b.subjectFor(ev.Source))
		}
	}
	if len(bodies) == 0 {
		return "", 0, nil
	}

	id := ""
	if kv := b.batches(); kv != nil {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", 0, err
		}
		candidate := hex.EncodeToString(raw[:])
		tenant := events[0].Tenant
		// The total is written before any message, so a consumer that is quick can never
		// make the batch look complete early.
		if _, err := kv.Put(ctx, candidate+".total", []byte(strconv.Itoa(len(bodies))+"|"+tenant)); err != nil {
			slog.Warn("ingest batch not tracked; the gate will not be able to wait for it", "err", err)
		} else {
			id = candidate
		}
	}
	for i, body := range bodies {
		msg := &nats.Msg{Subject: subjects[i], Data: body, Header: nats.Header{}}
		if id != "" {
			msg.Header.Set(hdrBatch, id)
			msg.Header.Set(hdrSeq, strconv.Itoa(i))
			msg.Header.Set(hdrTotal, strconv.Itoa(len(bodies)))
		}
		if _, err := b.js.PublishMsg(ctx, msg); err != nil {
			return "", 0, fmt.Errorf("publish %q: %w", subjects[i], err)
		}
	}
	return id, len(bodies), nil
}

// markApplied records that one message of a batch reached the graph. Best effort: a
// failure costs the gate its wait - it reports UNKNOWN - never an event.
func (b *Broker) markApplied(ctx context.Context, h nats.Header) {
	id, seq := h.Get(hdrBatch), h.Get(hdrSeq)
	kv := b.batches()
	if kv == nil || !batchIDRe.MatchString(id) {
		return
	}
	if _, err := strconv.Atoi(seq); err != nil {
		return
	}
	// One key per message, not a counter: a redelivered message rewrites its own key
	// instead of counting twice.
	if _, err := kv.Put(context.WithoutCancel(ctx), id+"."+seq, nil); err != nil {
		slog.Warn("could not record an applied ingest message", "batch", id, "err", err)
	}
}

// BatchStatus reports how much of a batch has been applied. An unknown or expired id
// yields a zero status and no error.
func (b *Broker) BatchStatus(ctx context.Context, id string) (BatchStatus, error) {
	st := BatchStatus{ID: id}
	kv := b.batches()
	if kv == nil || !batchIDRe.MatchString(id) {
		return st, nil
	}
	total, err := kv.Get(ctx, id+".total")
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	n, tenant, _ := strings.Cut(string(total.Value()), "|")
	st.Messages, _ = strconv.Atoi(n)
	st.Tenant = tenant

	lister, err := kv.ListKeysFiltered(ctx, id+".*")
	if err != nil {
		return st, err
	}
	var last time.Time
	for key := range lister.Keys() {
		if strings.HasSuffix(key, ".total") {
			continue
		}
		st.Applied++
		if e, err := kv.Get(ctx, key); err == nil && e.Created().After(last) {
			last = e.Created()
		}
	}
	if st.Complete() {
		st.AppliedAt = last
	}
	return st, nil
}

// splitEvent serialises ev as one message body, or as several when it exceeds limit:
// nodes first, in order, then edges, each chunk a copy of the event's other fields.
// Keeping the nodes ahead of the edges lets most edges land at once; one that arrives
// before its endpoint is parked by the store until it does (graph.EdgeParker).
func splitEvent(ev ontology.Event, limit int) ([][]byte, error) {
	whole, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}
	if len(whole) <= limit {
		return [][]byte{whole}, nil
	}
	var out [][]byte
	emit := func(nodes []ontology.Node, edges []ontology.Edge) error {
		chunk := ev
		chunk.Nodes, chunk.Edges = nodes, edges
		body, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		if len(body) <= limit {
			out = append(out, body)
			return nil
		}
		// The size estimate below undershoots only by JSON punctuation; if it did, halve.
		if len(nodes)+len(edges) <= 1 {
			return ErrTooLarge
		}
		if len(nodes) > 1 {
			if err := emitHalves(nodes, func(n []ontology.Node) error { return emitNodes(&out, ev, n, limit) }); err != nil {
				return err
			}
			return nil
		}
		return emitHalves(edges, func(e []ontology.Edge) error { return emitEdges(&out, ev, e, limit) })
	}
	envelope := ev
	envelope.Nodes, envelope.Edges = nil, nil
	env, _ := json.Marshal(envelope)
	budget := limit - len(env)

	size, start := 0, 0
	for i, n := range ev.Nodes {
		b, _ := json.Marshal(n)
		if size+len(b)+1 > budget && i > start {
			if err := emit(ev.Nodes[start:i], nil); err != nil {
				return nil, err
			}
			size, start = 0, i
		}
		size += len(b) + 1
	}
	if start < len(ev.Nodes) {
		if err := emit(ev.Nodes[start:], nil); err != nil {
			return nil, err
		}
	}
	size, start = 0, 0
	for i, e := range ev.Edges {
		b, _ := json.Marshal(e)
		if size+len(b)+1 > budget && i > start {
			if err := emit(nil, ev.Edges[start:i]); err != nil {
				return nil, err
			}
			size, start = 0, i
		}
		size += len(b) + 1
	}
	if start < len(ev.Edges) {
		if err := emit(nil, ev.Edges[start:]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func emitHalves[T any](xs []T, f func([]T) error) error {
	mid := len(xs) / 2
	if err := f(xs[:mid]); err != nil {
		return err
	}
	return f(xs[mid:])
}

func emitNodes(out *[][]byte, ev ontology.Event, nodes []ontology.Node, limit int) error {
	chunk := ev
	chunk.Nodes, chunk.Edges = nodes, nil
	parts, err := splitEvent(chunk, limit)
	if err != nil {
		return err
	}
	*out = append(*out, parts...)
	return nil
}

func emitEdges(out *[][]byte, ev ontology.Event, edges []ontology.Edge, limit int) error {
	chunk := ev
	chunk.Nodes, chunk.Edges = nil, edges
	parts, err := splitEvent(chunk, limit)
	if err != nil {
		return err
	}
	*out = append(*out, parts...)
	return nil
}
