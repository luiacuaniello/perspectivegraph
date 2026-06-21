package action

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aegisgraph/aegisgraph/internal/analyzer"
)

type mockGL struct {
	mu                sync.Mutex
	notes             []glNote
	nextID            int64
	gets, posts, puts int
}

func (m *mockGL) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if r.Header.Get("PRIVATE-TOKEN") == "" {
			http.Error(w, "no token", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			m.gets++
			_ = json.NewEncoder(w).Encode(m.notes)
		case http.MethodPost:
			m.posts++
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			m.nextID++
			m.notes = append(m.notes, glNote{ID: m.nextID, Body: in["body"]})
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(m.notes[len(m.notes)-1])
		case http.MethodPut:
			m.puts++
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			for i := range m.notes {
				m.notes[i].Body = in["body"]
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(m.notes[0])
		default:
			http.Error(w, "unexpected", http.StatusTeapot)
		}
	})
}

func TestGitLabCommenterCreateAndUpdate(t *testing.T) {
	mock := &mockGL{}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()
	ctx := context.Background()

	c := NewGitLabCommenter(GitLabConfig{Token: "glpat-x", BaseURL: srv.URL})

	c.OnCriticalPaths(ctx, []analyzer.AttackPath{samplePath(0.58)})
	if mock.posts != 1 || len(mock.notes) != 1 {
		t.Fatalf("expected 1 note created, posts=%d notes=%d", mock.posts, len(mock.notes))
	}
	if !strings.Contains(mock.notes[0].Body, "aegisgraph:attack-path:ap-test-1") {
		t.Error("note missing marker")
	}

	// Cold-cache commenter with changed body must update via marker, not repost.
	c2 := NewGitLabCommenter(GitLabConfig{Token: "glpat-x", BaseURL: srv.URL})
	c2.OnCriticalPaths(ctx, []analyzer.AttackPath{samplePath(0.42)})
	if mock.posts != 1 || mock.puts != 1 {
		t.Errorf("expected update not repost: posts=%d puts=%d", mock.posts, mock.puts)
	}
}
