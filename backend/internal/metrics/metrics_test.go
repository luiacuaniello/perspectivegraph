package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Requests are counted by class, not by exact status: an unbounded label (every code,
// or worse a path) is the classic way a metrics endpoint turns into a cardinality
// explosion that takes the scrape target down with it.
func TestCountBucketsStatusIntoClasses(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{200, "2xx"}, {201, "2xx"}, {204, "2xx"},
		{301, "3xx"}, {304, "3xx"},
		{400, "4xx"}, {403, "4xx"}, {429, "4xx"},
		{500, "5xx"}, {503, "5xx"},
	}
	for _, c := range cases {
		if got := codeClass(c.code); got != c.want {
			t.Errorf("codeClass(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

// Anything below 300 - including the odd 1xx - lands in 2xx rather than creating a
// class nobody dashboards on.
func TestCodeClassHasNoUnboundedFallthrough(t *testing.T) {
	for _, code := range []int{0, 100, 101, 299} {
		if got := codeClass(code); got != "2xx" {
			t.Errorf("codeClass(%d) = %q, want the 2xx bucket", code, got)
		}
	}
}

func TestCountIsVisibleThroughTheHandler(t *testing.T) {
	Count("ingest_test_handler", 503)

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics returned %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ingest_test_handler") {
		t.Error("the counted handler does not appear in the exposition output")
	}
	if !strings.Contains(body, `"5xx"`) && !strings.Contains(body, "5xx") {
		t.Error("the status class does not appear in the exposition output")
	}
}

// The handler serves a private registry. Runtime metrics are deliberately in it - a
// service without goroutine and process numbers is hard to operate - but a dependency
// that registers into prometheus.DefaultRegisterer must NOT be able to widen what this
// process publishes, which is the property a private registry actually buys.
func TestHandlerServesOurRegistryNotTheGlobalOne(t *testing.T) {
	stray := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pg_stray_metric_from_a_dependency_total",
		Help: "registered into the global default registry by something we do not control",
	})
	prometheus.MustRegister(stray)
	defer prometheus.Unregister(stray)
	stray.Inc()

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if strings.Contains(body, "pg_stray_metric_from_a_dependency_total") {
		t.Error("a metric registered globally leaked into our endpoint: the registry is not isolated")
	}
	// And the runtime collectors we *do* want are there.
	if !strings.Contains(body, "go_goroutines") {
		t.Error("runtime metrics are missing, so the service cannot be operated from its own endpoint")
	}
}
