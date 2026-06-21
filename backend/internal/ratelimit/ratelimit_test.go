package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDisabledIsPassThrough(t *testing.T) {
	l := New(0, 1) // rps 0 → disabled
	if l.Enabled() {
		t.Fatal("rps 0 must disable the limiter")
	}
	var nilLim *Limiter
	if nilLim.Enabled() {
		t.Fatal("nil limiter must be disabled")
	}
	// Middleware on a nil/disabled limiter returns the handler unchanged.
	called := 0
	h := nilLim.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called++ }))
	for i := 0; i < 100; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}
	if called != 100 {
		t.Errorf("disabled limiter throttled requests: %d/100", called)
	}
}

func TestBurstThenThrottle(t *testing.T) {
	// 1 rps, burst 3 → first 3 from an IP pass, the 4th is rejected.
	l := New(1, 3)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	req := func() int {
		r := httptest.NewRequest("POST", "/ingest/trivy", nil)
		r.RemoteAddr = "10.0.0.1:5555"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 3; i++ {
		if code := req(); code != 200 {
			t.Fatalf("request %d within burst should pass, got %d", i+1, code)
		}
	}
	if code := req(); code != http.StatusTooManyRequests {
		t.Errorf("4th request over budget should be 429, got %d", code)
	}
}

func TestPerIPIsolation(t *testing.T) {
	l := New(1, 1)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	hit := func(ip string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = ip + ":1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if hit("1.1.1.1") != 200 || hit("2.2.2.2") != 200 {
		t.Error("each IP gets its own bucket")
	}
	if hit("1.1.1.1") != http.StatusTooManyRequests {
		t.Error("the same IP exhausts its own bucket")
	}
}
