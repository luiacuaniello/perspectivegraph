// Package ratelimit provides a per-client-IP token-bucket HTTP middleware. The
// ingest and API servers accept large bodies and run non-trivial work per
// request (graph writes, Monte Carlo); without a rate cap a single source can
// exhaust the backend. This blunts that without external infrastructure.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a per-IP token-bucket rate limiter. Idle clients are evicted so the
// client map cannot grow without bound.
type Limiter struct {
	rate  rate.Limit
	burst int
	ttl   time.Duration

	mu      sync.Mutex
	clients map[string]*client
	lastGC  time.Time
}

type client struct {
	lim  *rate.Limiter
	seen time.Time
}

// New returns a limiter allowing `rps` requests/second per IP with the given
// burst. A non-positive rps disables limiting (Middleware is a pass-through).
func New(rps float64, burst int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    rate.Limit(rps),
		burst:   burst,
		ttl:     10 * time.Minute,
		clients: map[string]*client{},
		lastGC:  time.Now(),
	}
}

// Enabled reports whether limiting is active.
func (l *Limiter) Enabled() bool { return l != nil && l.rate > 0 }

func (l *Limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.lastGC) > l.ttl {
		for k, c := range l.clients {
			if now.Sub(c.seen) > l.ttl {
				delete(l.clients, k)
			}
		}
		l.lastGC = now
	}

	c := l.clients[ip]
	if c == nil {
		c = &client{lim: rate.NewLimiter(l.rate, l.burst)}
		l.clients[ip] = c
	}
	c.seen = now
	return c.lim.Allow()
}

// Middleware wraps next, rejecting requests that exceed the per-IP budget with
// 429. When limiting is disabled it returns next unchanged.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	if !l.Enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP uses the connecting peer's address. We deliberately do NOT trust
// X-Forwarded-For (spoofable); terminate TLS/proxy in front and the peer is the
// proxy, which is the right unit to limit anyway for a single-tenant edge.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
