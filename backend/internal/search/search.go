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
	"net/http"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/httpx"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Hit is a single full-text search result.
type Hit struct {
	ID    string  `json:"id"`
	Label string  `json:"label"`
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// Indexer indexes graph nodes and answers full-text queries, isolated per
// tenant (each tenant gets its own index).
type Indexer interface {
	Enabled() bool
	Index(ctx context.Context, tenant string, nodes []ontology.Node) error
	Search(ctx context.Context, tenant, query string, size int) ([]Hit, error)
}

// New returns an OpenSearch-backed indexer, or a no-op one when url is empty.
func New(url string) Indexer {
	if url == "" {
		return Noop{}
	}
	return &OpenSearch{
		url:    url,
		prefix: "perspective-nodes",
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Noop is the disabled indexer.
type Noop struct{}

func (Noop) Enabled() bool                                              { return false }
func (Noop) Index(context.Context, string, []ontology.Node) error       { return nil }
func (Noop) Search(context.Context, string, string, int) ([]Hit, error) { return nil, nil }

// OpenSearch indexes nodes into an OpenSearch (or Elasticsearch) cluster, one
// index per tenant for isolation.
type OpenSearch struct {
	url    string
	prefix string
	client *http.Client
}

func (o *OpenSearch) Enabled() bool { return true }

// indexFor returns the per-tenant index name.
func (o *OpenSearch) indexFor(tenant string) string {
	if tenant == "" {
		tenant = "default"
	}
	return o.prefix + "-" + tenant
}

// Index bulk-upserts nodes keyed by their graph id (idempotent re-indexing).
func (o *OpenSearch) Index(ctx context.Context, tenant string, nodes []ontology.Node) error {
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
	url := fmt.Sprintf("%s/%s/_bulk", o.url, o.indexFor(tenant))
	// A _bulk request can come back 200 OK with per-item failures (mapping
	// conflicts, oversized fields, …): check the items, not just the status.
	var resp struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			ID     string `json:"_id"`
			Status int    `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := o.do(ctx, http.MethodPost, url, "application/x-ndjson", body.Bytes(), &resp); err != nil {
		return err
	}
	if resp.Errors {
		failed, first := 0, ""
		for _, item := range resp.Items {
			for _, r := range item {
				if r.Error != nil {
					failed++
					if first == "" {
						first = fmt.Sprintf("%s: %s: %s", r.ID, r.Error.Type, r.Error.Reason)
					}
				}
			}
		}
		return fmt.Errorf("bulk index: %d/%d documents rejected (first: %s)", failed, len(nodes), first)
	}
	return nil
}

// Search runs a multi_match query across the indexed fields of a tenant's index.
func (o *OpenSearch) Search(ctx context.Context, tenant, query string, size int) ([]Hit, error) {
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
	// ignore_unavailable: a tenant that has indexed nothing yet has no index,
	// which should yield empty results rather than a 404.
	url := fmt.Sprintf("%s/%s/_search?ignore_unavailable=true", o.url, o.indexFor(tenant))
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
	return httpx.Do(ctx, o.client, method, url, nil, contentType, body, out)
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
