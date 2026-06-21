// Package search provides an optional full-text index over graph nodes. The
// graph answers "how are things connected?"; OpenSearch answers "show me
// everything matching log4shell / payments / CVE-2024-1234" instantly. It is
// entirely optional: with no OPENSEARCH_URL the Noop indexer is used and the
// rest of the system is unaffected.
package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

// Hit is a single full-text search result.
type Hit struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// Indexer indexes graph nodes and answers full-text queries.
type Indexer interface {
	Enabled() bool
	Index(ctx context.Context, nodes []ontology.Node) error
	Search(ctx context.Context, query string, size int) ([]Hit, error)
}

// New returns an OpenSearch-backed indexer, or a no-op one when url is empty.
func New(url string) Indexer {
	if url == "" {
		return Noop{}
	}
	return &OpenSearch{
		url:    url,
		index:  "aegis-nodes",
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Noop is the disabled indexer.
type Noop struct{}

func (Noop) Enabled() bool                                      { return false }
func (Noop) Index(context.Context, []ontology.Node) error       { return nil }
func (Noop) Search(context.Context, string, int) ([]Hit, error) { return nil, nil }

// OpenSearch indexes nodes into an OpenSearch (or Elasticsearch) cluster.
type OpenSearch struct {
	url    string
	index  string
	client *http.Client
}

func (o *OpenSearch) Enabled() bool { return true }

// Index bulk-upserts nodes keyed by their graph id (idempotent re-indexing).
func (o *OpenSearch) Index(ctx context.Context, nodes []ontology.Node) error {
	if len(nodes) == 0 {
		return nil
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, n := range nodes {
		meta := map[string]map[string]string{"index": {"_id": n.ID}}
		if err := enc.Encode(meta); err != nil {
			return err
		}
		if err := enc.Encode(toDoc(n)); err != nil {
			return err
		}
	}
	url := fmt.Sprintf("%s/%s/_bulk", o.url, o.index)
	return o.do(ctx, http.MethodPost, url, "application/x-ndjson", body.Bytes(), nil)
}

// Search runs a multi_match query across the indexed fields.
func (o *OpenSearch) Search(ctx context.Context, query string, size int) ([]Hit, error) {
	if size <= 0 {
		size = 25
	}
	q := map[string]any{
		"size": size,
		"query": map[string]any{
			"multi_match": map[string]any{
				"query":  query,
				"fields": []string{"name^2", "label", "id", "severity", "cwe", "message"},
			},
		},
	}
	payload, _ := json.Marshal(q)

	var resp struct {
		Hits struct {
			Hits []struct {
				Score  float64 `json:"_score"`
				Source struct {
					ID    string `json:"id"`
					Label string `json:"label"`
					Name  string `json:"name"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	url := fmt.Sprintf("%s/%s/_search", o.url, o.index)
	if err := o.do(ctx, http.MethodPost, url, "application/json", payload, &resp); err != nil {
		return nil, err
	}

	hits := make([]Hit, 0, len(resp.Hits.Hits))
	for _, h := range resp.Hits.Hits {
		hits = append(hits, Hit{ID: h.Source.ID, Label: h.Source.Label, Name: h.Source.Name, Score: h.Score})
	}
	return hits, nil
}

func (o *OpenSearch) do(ctx context.Context, method, url, contentType string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("opensearch %s %s: %s: %s", method, url, resp.Status, bytes.TrimSpace(msg))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// toDoc flattens a node into a searchable document (core fields + a few
// well-known properties).
func toDoc(n ontology.Node) map[string]any {
	doc := map[string]any{
		"id":    n.ID,
		"label": string(n.Label),
		"name":  n.Name,
	}
	for _, k := range []string{ontology.PropSeverity, "cwe", "message", "path", "check_id"} {
		if v, ok := n.Properties[k]; ok {
			doc[k] = v
		}
	}
	return doc
}
