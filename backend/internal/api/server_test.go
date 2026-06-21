package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryDepth(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"flat", `{ posture { criticalPaths } }`, 2},
		{"nested path", `{ attackPaths { nodes { id } } }`, 3},
		{"fragment resolved", `query { attackPaths { ...f } } fragment f on AttackPath { nodes { id } }`, 3},
	}
	for _, c := range cases {
		got, err := queryDepth(c.query)
		if err != nil {
			t.Fatalf("%s: parse error: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: depth = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestQueryDepthCyclicFragmentDoesNotHang(t *testing.T) {
	// A self-referential fragment is invalid GraphQL, but a malicious client can
	// still send it — the guard must terminate, not recurse forever.
	q := `query { attackPaths { ...a } } fragment a on AttackPath { nodes { id } ...a }`
	got, err := queryDepth(q)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if got <= maxQueryDepth {
		t.Errorf("cyclic fragment depth = %d, want > %d (rejected)", got, maxQueryDepth)
	}
}

func TestCORSAllowlist(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	cases := []struct {
		name     string
		origins  []string
		origin   string
		wantACAO string
	}{
		{"allow-listed origin is echoed", []string{"http://localhost:5173"}, "http://localhost:5173", "http://localhost:5173"},
		{"unlisted origin is not echoed", []string{"http://localhost:5173"}, "https://evil.example", ""},
		{"wildcard allows any origin", []string{"*"}, "https://evil.example", "*"},
		{"empty list disables CORS", nil, "http://localhost:5173", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &API{corsOrigins: c.origins}
			req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			rec := httptest.NewRecorder()
			a.withCORS(next).ServeHTTP(rec, req)
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != c.wantACAO {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, c.wantACAO)
			}
		})
	}
}

func TestCORSPreflightShortCircuits(t *testing.T) {
	a := &API{corsOrigins: []string{"http://localhost:3000"}}
	reached := false
	h := a.withCORS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rec.Code)
	}
	if reached {
		t.Error("OPTIONS preflight must not reach the wrapped handler")
	}
}
