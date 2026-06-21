package action

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// mockGH is a tiny stand-in for the GitHub issues-comments API.
type mockGH struct {
	mu                   sync.Mutex
	comments             []ghComment
	nextID               int64
	gets, posts, patches int
}

func (m *mockGH) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(strings.Split(r.URL.Path, "?")[0], "/comments"):
			m.gets++
			_ = json.NewEncoder(w).Encode(m.comments)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments"):
			m.posts++
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			m.nextID++
			c := ghComment{ID: m.nextID, Body: in["body"]}
			m.comments = append(m.comments, c)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(c)
		case r.Method == http.MethodPatch:
			m.patches++
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			// last path segment is the comment id; just update the only comment
			for i := range m.comments {
				m.comments[i].Body = in["body"]
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(m.comments[0])
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
		}
	})
}

func samplePath(score float64) analyzer.AttackPath {
	return analyzer.AttackPath{
		ID:    "ap-test-1",
		Score: score,
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-alb",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "img", Label: ontology.LabelImage, Name: "payments-api:1.4.2",
				Properties: map[string]any{ontology.PropRepoSlug: "acme/payments-api", ontology.PropPRNumber: 42}},
			{ID: "cve", Label: ontology.LabelCVE, Name: "CVE-2021-44228",
				Properties: map[string]any{"fixed_version": "2.15.0", ontology.PropSeverity: "CRITICAL"}},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "admin",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeExposes, From: "lb", To: "img", Probability: 0.9},
			{EdgeType: ontology.EdgeAffects, From: "img", To: "cve", Probability: 0.9},
			{EdgeType: ontology.EdgeExploits, From: "cve", To: "role", Probability: 0.8},
		},
	}
}

func TestGitHubCommenterCreateDedupUpdate(t *testing.T) {
	mock := &mockGH{}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()
	ctx := context.Background()

	c := NewGitHubCommenter(GitHubConfig{Token: "test-token", BaseURL: srv.URL})
	path := samplePath(0.58)

	// 1. First pass → one comment created.
	c.OnCriticalPaths(ctx, []analyzer.AttackPath{path})
	if mock.posts != 1 {
		t.Fatalf("expected 1 POST, got %d", mock.posts)
	}
	if len(mock.comments) != 1 {
		t.Fatalf("expected 1 comment, got %d", len(mock.comments))
	}
	body := mock.comments[0].Body
	for _, want := range []string{"perspectivegraph:attack-path:ap-test-1", "PerspectiveGraph", "2.15.0", "58%"} {
		if !strings.Contains(body, want) {
			t.Errorf("comment body missing %q\n---\n%s", want, body)
		}
	}

	// 2. Same path again → in-memory dedup skips the API entirely.
	c.OnCriticalPaths(ctx, []analyzer.AttackPath{path})
	if mock.posts != 1 || mock.gets != 1 {
		t.Errorf("identical pass should hit no API: posts=%d gets=%d", mock.posts, mock.gets)
	}

	// 3. A fresh commenter (cold cache) with a changed body must UPDATE the
	//    existing comment (found by marker), not create a new one.
	c2 := NewGitHubCommenter(GitHubConfig{Token: "test-token", BaseURL: srv.URL})
	c2.OnCriticalPaths(ctx, []analyzer.AttackPath{samplePath(0.42)})
	if mock.posts != 1 {
		t.Errorf("expected no new POST, got posts=%d", mock.posts)
	}
	if mock.patches != 1 {
		t.Errorf("expected 1 PATCH (update), got %d", mock.patches)
	}
	if len(mock.comments) != 1 {
		t.Errorf("should still be a single comment, got %d", len(mock.comments))
	}
	if !strings.Contains(mock.comments[0].Body, "42%") {
		t.Errorf("comment should have been updated to the new score")
	}
}

func TestGitHubCommenterSkipsWhenNoPRContext(t *testing.T) {
	mock := &mockGH{}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	c := NewGitHubCommenter(GitHubConfig{Token: "test-token", BaseURL: srv.URL})
	path := samplePath(0.58)
	path.Nodes[1].Properties = nil // strip PR context from the image node

	c.OnCriticalPaths(context.Background(), []analyzer.AttackPath{path})
	if mock.posts != 0 || mock.gets != 0 {
		t.Errorf("no PR context should mean no API calls: posts=%d gets=%d", mock.posts, mock.gets)
	}
}

func TestPRTarget(t *testing.T) {
	slug, num, ok := prTarget(samplePath(0.5))
	if !ok || slug != "acme/payments-api" || num != 42 {
		t.Fatalf("prTarget = (%q,%d,%v), want (acme/payments-api,42,true)", slug, num, ok)
	}
}
