package search

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestNoopDisabled(t *testing.T) {
	if New("").Enabled() {
		t.Error("empty URL should yield a disabled indexer")
	}
}

func TestIndexBulkPayload(t *testing.T) {
	var gotBody string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"errors":false,"items":[]}`))
	}))
	defer srv.Close()

	idx := New(srv.URL)
	if !idx.Enabled() {
		t.Fatal("expected enabled indexer")
	}
	err := idx.Index(context.Background(), "default", []ontology.Node{
		{ID: "CVE:abc", Label: ontology.LabelCVE, Name: "CVE-2021-44228",
			Properties: map[string]any{ontology.PropSeverity: "CRITICAL"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotPath, "/_bulk") {
		t.Errorf("expected bulk endpoint, got %s", gotPath)
	}
	// NDJSON: action line then doc line.
	lines := strings.Split(strings.TrimSpace(gotBody), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 NDJSON lines, got %d: %q", len(lines), gotBody)
	}
	if !strings.Contains(lines[0], `"_id":"CVE:abc"`) {
		t.Errorf("action line missing _id: %s", lines[0])
	}
	if !strings.Contains(lines[1], "CVE-2021-44228") {
		t.Errorf("doc line missing name: %s", lines[1])
	}
}

func TestSearchParsesHits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_search") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		resp := map[string]any{
			"hits": map[string]any{
				"hits": []map[string]any{
					{"_score": 4.2, "_source": map[string]any{"id": "CVE:abc", "label": "CVE", "name": "CVE-2021-44228"}},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	hits, err := New(srv.URL).Search(context.Background(), "default", "log4shell", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Name != "CVE-2021-44228" || hits[0].Score != 4.2 {
		t.Fatalf("unexpected hits: %+v", hits)
	}
}

// A tenant becomes part of an index name, and an index name in an OpenSearch path is an
// expression: "*" matches every index and "a,b" names two. The tenant a search ran under
// was the caller's, as it came - a token's claim - so a tenant of "*" searched every
// tenant's assets, while ingest wrote under the normalized name, which left "Acme"
// searching an index nobody writes. Both now go through graph.NormalizeTenant.
func TestATenantSearchesOnlyTheIndexItWritesTo(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write([]byte(`{"errors":false,"items":[],"hits":{"hits":[]}}`))
	}))
	defer srv.Close()
	idx := New(srv.URL)
	ctx := context.Background()
	node := []ontology.Node{{ID: "VM:a", Label: ontology.LabelVirtualMachine, Name: "a"}}

	written := func(tenant string) string {
		paths = nil
		if err := idx.Index(ctx, tenant, node); err != nil {
			t.Fatal(err)
		}
		return strings.TrimSuffix(paths[0], "/_bulk")
	}
	searched := func(tenant string) string {
		paths = nil
		if _, err := idx.Search(ctx, tenant, "a", 10); err != nil {
			t.Fatal(err)
		}
		return strings.TrimSuffix(paths[0], "/_search")
	}

	acme := written("acme")
	for _, tenant := range []string{"*", "acme*", "x,perspective-nodes-acme", "_all", "x/../perspective-nodes-acme", "x?q=1#"} {
		got := searched(tenant)
		if strings.ContainsAny(got, "*,?#") || strings.Count(got, "/") != 1 {
			t.Errorf("tenant %q searched %q: not one plain index", tenant, got)
		}
		if got == acme {
			t.Errorf("tenant %q searched acme's index", tenant)
		}
	}
	// Ingest indexes under the tenant the normalizer resolved; a search has the caller's.
	for _, tenant := range []string{"Acme", "victim-corp", " Globex "} {
		if w, s := written(graph.NormalizeTenant(tenant)), searched(tenant); w != s {
			t.Errorf("tenant %q is indexed in %q and searches %q", tenant, w, s)
		}
	}
}
