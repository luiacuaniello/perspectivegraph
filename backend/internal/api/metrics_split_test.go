package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// /metrics is open and unthrottled so a scrape never starves, but several series carry a
// `tenant` label - so on a reachable API port it lets anyone enumerate tenants and read
// each one's current critical-path count. METRICS_ADDR moves it to a listener an operator
// can keep internal; this is the half that takes it off the API mux.
func TestMetricsLeavesTheAPIMuxWhenServedElsewhere(t *testing.T) {
	for _, tc := range []struct {
		name      string
		elsewhere bool
		want      int
	}{
		{"default keeps it on the API port", false, http.StatusOK},
		{"METRICS_ADDR takes it off", true, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(nil, nil, nil).WithMetricsElsewhere(tc.elsewhere)
			h, err := a.Handler()
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if rec.Code != tc.want {
				t.Fatalf("GET /metrics = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// Moving metrics must not disturb anything else on the mux - /healthz in particular is
// what the readiness probe hits.
func TestMovingMetricsLeavesHealthzAlone(t *testing.T) {
	h, err := New(nil, nil, nil).WithMetricsElsewhere(true).Handler()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}
}
