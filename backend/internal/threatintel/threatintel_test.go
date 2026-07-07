package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEdgeProbability(t *testing.T) {
	cases := []struct {
		name     string
		in       Intel
		fallback float64
		want     float64
	}{
		{"kev floors high over low epss", Intel{KEV: true, EPSS: 0.2}, 0.7, 0.95},
		{"kev keeps very high epss", Intel{KEV: true, EPSS: 0.97}, 0.7, 0.97},
		{"epss wins when no kev", Intel{EPSS: 0.43}, 0.7, 0.43},
		{"fallback when no intel", Intel{}, 0.7, 0.7},
	}
	for _, c := range cases {
		if got := c.in.EdgeProbability(c.fallback); got != c.want {
			t.Errorf("%s: EdgeProbability(%v) = %v, want %v", c.name, c.fallback, got, c.want)
		}
	}
}

func TestTraversalFromEPSS(t *testing.T) {
	defer SetTraversalGamma(1.0) // restore the identity for the other tests

	SetTraversalGamma(1.0) // default: EPSS used as-is
	if got := TraversalFromEPSS(0.43); got != 0.43 {
		t.Errorf("identity: TraversalFromEPSS(0.43) = %v, want 0.43", got)
	}

	SetTraversalGamma(0.5) // opt-in lift
	lifted := TraversalFromEPSS(0.04)
	if !(lifted > 0.04 && lifted <= 1) {
		t.Errorf("lift: TraversalFromEPSS(0.04) = %v, want in (0.04, 1]", lifted)
	}
	if TraversalFromEPSS(0.5) <= TraversalFromEPSS(0.1) {
		t.Error("lift must be monotone increasing in EPSS")
	}
	if TraversalFromEPSS(0) != 0 || TraversalFromEPSS(1) != 1 {
		t.Error("lift must fix the endpoints 0 and 1")
	}
	if got := (Intel{EPSS: 0.04}).EdgeProbability(0.7); got != lifted {
		t.Errorf("EdgeProbability should apply the traversal map: got %v, want %v", got, lifted)
	}
	// KEV is observed exploitation, not a prediction to lift.
	if got := (Intel{KEV: true, EPSS: 0.2}).EdgeProbability(0.7); got != 0.95 {
		t.Errorf("KEV branch must not be lifted: got %v, want 0.95", got)
	}
}

func TestLiveScoresMergesKEVandEPSS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "known_exploited"):
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`))
		case strings.Contains(r.URL.Path, "epss"):
			// echoes EPSS only for the log4shell CVE
			_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2021-44228","epss":"0.94358","percentile":"0.99964"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	src := New(true, srv.URL+"/known_exploited.json", srv.URL+"/epss")
	if !src.Enabled() {
		t.Fatal("source should be enabled")
	}
	got := src.Scores(context.Background(), []string{"CVE-2021-44228", "CVE-2000-0001"})

	log4shell, ok := got["CVE-2021-44228"]
	if !ok {
		t.Fatal("expected intel for CVE-2021-44228")
	}
	if !log4shell.KEV {
		t.Error("CVE-2021-44228 should be flagged KEV")
	}
	if log4shell.EPSS < 0.94 || log4shell.EPSS > 0.95 {
		t.Errorf("EPSS = %v, want ~0.9436", log4shell.EPSS)
	}
	if _, present := got["CVE-2000-0001"]; present {
		t.Error("a CVE with neither KEV nor EPSS must be omitted")
	}

	// Second call serves from cache without re-hitting the server (closed check
	// is implicit: TTL is hours, so no new request is needed - just verify it
	// still returns the data).
	again := src.Scores(context.Background(), []string{"CVE-2021-44228"})
	if !again["CVE-2021-44228"].KEV {
		t.Error("cached lookup lost the KEV flag")
	}
}

func TestNewDisabledReturnsNoop(t *testing.T) {
	src := New(false, "", "")
	if src.Enabled() {
		t.Fatal("disabled source must not be enabled")
	}
	if got := src.Scores(context.Background(), []string{"CVE-2021-44228"}); got != nil {
		t.Errorf("Noop.Scores = %v, want nil", got)
	}
}
