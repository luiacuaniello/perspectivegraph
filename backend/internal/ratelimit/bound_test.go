package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The per-IP table is keyed by the peer address and swept only every TTL, so between two
// sweeps it had no ceiling: an IPv6 /64 offers 2^64 keys, and the middleware that exists
// to prevent resource exhaustion would have been the way to cause it.
func TestClientTableIsBoundedUnderIPFlood(t *testing.T) {
	l := New(100, 10).WithMaxClients(500)

	for i := 0; i < 100_000; i++ {
		l.allow(fmt.Sprintf("2001:db8::%x", i))
	}

	if got := l.TrackedClients(); got > 500 {
		t.Fatalf("tracking %d clients after a 100k-address flood, cap is 500", got)
	}
}

// Clients admitted before the cap keep their own budget: the overflow path must not
// disturb the accounting of everyone already known.
func TestKnownClientsKeepTheirOwnBudget(t *testing.T) {
	l := New(1, 5).WithMaxClients(10)

	for i := 0; i < 5; i++ {
		if !l.allow("10.0.0.1") {
			t.Fatalf("burst request %d denied to a known client", i)
		}
	}
	if l.allow("10.0.0.1") {
		t.Error("a known client was served past its burst")
	}

	for i := 0; i < 1000; i++ { // flood past the cap
		l.allow(fmt.Sprintf("10.9.%d.%d", i/256, i%256))
	}
	if l.allow("10.0.0.1") {
		t.Error("the flood refilled a known client's bucket")
	}
}

// Overflow callers share one bucket. That is the middle path: denying outright would let
// a flood lock out every new legitimate client, and a fresh per-request limiter would
// allow everything, since a new token bucket starts full. The point of the assertion is
// that overflow traffic is actually limited rather than waved through.
func TestOverflowTrafficIsStillLimited(t *testing.T) {
	l := New(1, 3).WithMaxClients(2)

	l.allow("known-1")
	l.allow("known-2")

	allowed := 0
	for i := 0; i < 500; i++ {
		if l.allow(fmt.Sprintf("flood-%d", i)) {
			allowed++
		}
	}
	if allowed > 10 {
		t.Fatalf("%d of 500 overflow requests allowed - the shared bucket is not limiting", allowed)
	}
	if allowed == 0 {
		t.Error("no overflow request allowed at all - new clients are locked out entirely")
	}
}

// The middleware must keep behaving normally below the cap.
func TestMiddlewareStillLimitsPerIP(t *testing.T) {
	l := New(1, 2)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	codes := map[int]int{}
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.1.1.1:5000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		codes[rec.Code]++
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("no request was rate limited: %v", codes)
	}
	if codes[http.StatusOK] == 0 {
		t.Fatalf("every request was rejected: %v", codes)
	}
}
