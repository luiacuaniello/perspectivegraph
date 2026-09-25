package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type batchPublisher struct {
	capturingPublisher
	batches int
	err     error
}

func (p *batchPublisher) PublishBatch(_ context.Context, events []ontology.Event) (string, int, error) {
	if p.err != nil {
		return "", 0, p.err
	}
	p.batches++
	p.got = append(p.got, events...)
	return "0123456789abcdef0123456789abcdef", 3, nil
}

type tooBig struct{}

func (tooBig) Error() string  { return "one element is too large" }
func (tooBig) TooLarge() bool { return true }

// One request is one batch, and the response names it, so the gate can wait for all of
// it to reach the graph before it trusts a verdict.
func TestAnIngestIsPublishedAsOneNamedBatch(t *testing.T) {
	pub := &batchPublisher{}
	h := NewServer(pub).Handler()
	body, _ := json.Marshal(ontology.Event{Source: "k8s", Nodes: []ontology.Node{{ID: "n", Label: ontology.LabelContainer}}})
	req := httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(string(body)))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Tenant: "acme"}))
	rec := do(h, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var resp struct {
		Batch    string `json:"batch"`
		Messages int    `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if pub.batches != 1 || resp.Batch != "0123456789abcdef0123456789abcdef" || resp.Messages != 3 {
		t.Errorf("batches=%d response=%+v; want one batch, named, with its message count", pub.batches, resp)
	}
	if pub.got[0].Tenant != "acme" {
		t.Errorf("tenant %q, want the principal's", pub.got[0].Tenant)
	}
}

// An element too large for any message cannot succeed on a retry, so it is not a 502:
// the sender is told the request itself is too large.
func TestAnElementTooLargeForTheBusIs413(t *testing.T) {
	h := NewServer(&batchPublisher{err: tooBig{}}).Handler()
	body, _ := json.Marshal(ontology.Event{Source: "k8s", Nodes: []ontology.Node{{ID: "n", Label: ontology.LabelContainer}}})
	rec := do(h, httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(string(body))))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	if rec := do(NewServer(&batchPublisher{err: errors.New("nats down")}).Handler(),
		httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(string(body)))); rec.Code != http.StatusBadGateway {
		t.Fatalf("a bus failure answered %d, want 502", rec.Code)
	}
}
