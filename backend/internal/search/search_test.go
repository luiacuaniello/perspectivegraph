package search

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
