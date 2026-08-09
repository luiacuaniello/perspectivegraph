package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
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

// unreachableStore stands in for a graph store whose database has gone away after the
// process started - the case the startup-time degraded flag cannot see.
type unreachableStore struct {
	graph.Store
	err error
}

func (u unreachableStore) Ping(context.Context) error { return u.err }

func apiWithStore(t *testing.T, pingErr error) *API {
	t.Helper()
	ctx := context.Background()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) {
		return unreachableStore{Store: memory.New(), err: pingErr}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(mgr, nil, nil)
}

// The defect this closes: `degraded` is decided ONCE at construction, so a process whose
// database died afterwards kept answering "ok" while every query returned an error. An
// orchestrator therefore kept routing to it, and any alert built on this probe never
// fired. Verified by hand first - stopping Postgres under a running stack left /healthz
// at 200 while GraphQL returned "no such host".
func TestHealthzFailsWhenTheStoreIsUnreachable(t *testing.T) {
	rec := httptest.NewRecorder()
	apiWithStore(t, errors.New("dial tcp: no such host")).writeHealth(rec)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 - the pod would stay in the Service with a dead database", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no such host") {
		t.Errorf("the response does not say why: %q", rec.Body.String())
	}
}

// A reachable store is healthy, so a working deployment is not taken out of service by
// its own probe.
func TestHealthzIsOKWhenTheStoreAnswers(t *testing.T) {
	rec := httptest.NewRecorder()
	apiWithStore(t, nil).writeHealth(rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// The probe runs several times a minute, per replica, for ever. Without memoisation
// that is a database round trip each time, and a kubelet with a short period would put
// a steady query load on the store just to ask whether it is there.
func TestReadinessIsMemoisedBetweenProbes(t *testing.T) {
	var pings atomic.Int64
	mgr, err := graph.NewManager(context.Background(), func(context.Context, string) (graph.Store, error) {
		return countingStore{Store: memory.New(), n: &pings}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a := New(mgr, nil, nil)

	for i := 0; i < 20; i++ {
		a.writeHealth(httptest.NewRecorder())
	}
	if got := pings.Load(); got != 1 {
		t.Errorf("%d store pings for 20 probes; the result is meant to be cached for %v", got, readinessTTL)
	}
}

type countingStore struct {
	graph.Store
	n *atomic.Int64
}

func (c countingStore) Ping(context.Context) error { c.n.Add(1); return nil }
