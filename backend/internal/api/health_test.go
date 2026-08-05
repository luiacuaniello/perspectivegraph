package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Health has to be able to say no. Returning 200 unconditionally made the Kubernetes
// readiness probe prove only that the HTTP server was listening - so a backend whose
// graph store had fallen back to memory kept receiving traffic and kept answering "no
// attack paths" over an empty graph, which reads as good news.
func TestHealthzFailsWhenDegraded(t *testing.T) {
	rec := httptest.NewRecorder()
	api := &API{degraded: "graph store fell back to memory"}
	api.writeHealth(rec)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 so an orchestrator stops routing here", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "fell back to memory") {
		t.Errorf("the response does not say why: %q", rec.Body.String())
	}
}

func TestHealthzIsOKWhenHealthy(t *testing.T) {
	rec := httptest.NewRecorder()
	(&API{}).writeHealth(rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// WithDegraded is the only way the flag is set, and an empty reason must mean healthy -
// a deployment on the in-memory store BY DESIGN (the demo profile) is not degraded.
func TestWithDegradedEmptyMeansHealthy(t *testing.T) {
	rec := httptest.NewRecorder()
	(&API{}).WithDegraded("").writeHealth(rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("an empty reason made the instance unhealthy: %d", rec.Code)
	}
}
