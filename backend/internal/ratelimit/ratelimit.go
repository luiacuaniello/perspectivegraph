// Package ratelimit provides a per-client-IP token-bucket HTTP middleware. The
// ingest and API servers accept large bodies and run non-trivial work per
// request (graph writes, Monte Carlo); without a rate cap a single source can
// exhaust the backend. This blunts that without external infrastructure.
package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
)

// Limiter is a per-IP token-bucket rate limiter. Idle clients are evicted so the
// client map cannot grow without bound.
type Limiter struct {
	ips *clientip.Resolver

	rate  rate.Limit
	burst int
	ttl   time.Duration

	maxClients int
	// overflow is the shared bucket serving callers we refuse to allocate per-IP state
	// for once maxClients is reached. One limiter, created up front, so the overflow
	// path itself allocates nothing.
	overflow *rate.Limiter

	mu      sync.Mutex
	clients map[string]*client
	lastGC  time.Time
}

// DefaultMaxClients bounds the per-IP table. At roughly 200 bytes per entry - key,
// client struct and the rate.Limiter behind it - 100k entries is about 20 MB, which is
// a footprint an operator can reason about, and far more distinct peers than a single
// backend legitimately serves inside one TTL.
const DefaultMaxClients = 100_000

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
		rate:       rate.Limit(rps),
		burst:      burst,
		ttl:        10 * time.Minute,
		maxClients: DefaultMaxClients,
		overflow:   rate.NewLimiter(rate.Limit(rps), burst),
		clients:    map[string]*client{},
		lastGC:     time.Now(),
	}
}

// WithMaxClients overrides the per-IP table ceiling. Returns the limiter for chaining.
func (l *Limiter) WithMaxClients(n int) *Limiter {
	if n > 0 {
		l.maxClients = n
	}
	return l
}

// TrackedClients reports the current size of the per-IP table, so a test can assert the
// bound holds and an operator can see the footprint.
func (l *Limiter) TrackedClients() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients)
}

// Enabled reports whether limiting is active.
func (l *Limiter) Enabled() bool { return l != nil && l.rate > 0 }

func (l *Limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.lastGC) > l.ttl || len(l.clients) > l.maxClients {
		for k, c := range l.clients {
			if now.Sub(c.seen) > l.ttl {
				delete(l.clients, k)
			}
		}
		l.lastGC = now
	}
	// The sweep above is time-based, so between two passes the map had no ceiling at
	// all - and the key is the peer address, which the caller picks. A single IPv6 /64
	// supplies 2^64 of them, so ten minutes of rotation could grow this map to
	// gigabytes: the control meant to stop resource exhaustion became a way to cause
	// it. When even a fresh sweep leaves us over the cap, every entry is younger than
	// the TTL - the flood case - so stop minting per-IP state.
	//
	// Overflow callers share ONE bucket rather than being denied outright or waved
	// through. Denying would let a flood lock out every genuinely new client; a fresh
	// per-request limiter would allow everything, since a new token bucket starts full.
	// Sharing degrades new arrivals during an attack without ever unbounding memory,
	// and the already-tracked clients keep their own budgets untouched.
	if _, known := l.clients[ip]; !known && len(l.clients) >= l.maxClients {
		return l.overflow.Allow()
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
		if !l.allow(l.ips.Of(r)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WithClientIP sets how the limiter identifies a client. Nil (the default) trusts no
// proxy and keys on the connecting peer.
//
// The limiter and the brute-force lockout MUST resolve the address the same way. They
// did not once before: the limiter used the peer while the lockout read
// X-Forwarded-For, and rotating that header walked straight past the lockout. Sharing
// one resolver is what keeps the two from drifting apart again.
func (l *Limiter) WithClientIP(r *clientip.Resolver) *Limiter {
	if l != nil {
		l.ips = r
	}
	return l
}
