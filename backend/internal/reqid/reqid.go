// Package reqid stamps every HTTP request with an id and carries it in the context, so
// one call can be followed across the three places this system records what happened.
//
// Without it the three are unjoinable. The audit log says a principal opened a
// remediation PR; the application log says a connector timed out; the metrics say a pass
// ran long - and nothing says those were the same request. For a tool whose output is
// evidence about a security incident, "I cannot tell you which call did this" is a poor
// answer, and it is the one this product had.
//
// The id is echoed back in X-Request-Id so a person reporting a problem can quote it,
// and an inbound X-Request-Id is honoured so a gateway or client that already correlates
// keeps its own thread rather than having a second identifier grafted on.
package reqid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// Header is the request/response header carrying the id.
const Header = "X-Request-Id"

type ctxKey struct{}

// maxInboundLen bounds an id we did not generate. It is echoed into responses and into
// the audit log, so an unbounded one lets a caller pad every record it touches; the
// character filter below keeps it from carrying structure into either.
const maxInboundLen = 64

// NewContext returns ctx carrying id.
func NewContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the request id, or "" when there is none - a background job, a
// test, or any path that did not come through the middleware.
func FromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// New returns a fresh random id.
func New() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-0000000000000000" // never fail a request over a correlation id
	}
	return "req-" + hex.EncodeToString(b[:])
}

// Middleware assigns an id to every request, puts it in the context and echoes it in the
// response.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitise(r.Header.Get(Header))
		if id == "" {
			id = New()
		}
		w.Header().Set(Header, id)
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), id)))
	})
}

// sanitise accepts an inbound id only if it is short and made of characters that cannot
// forge structure once it reaches a log line, an audit record or a response header.
// Anything else is dropped and replaced with one we generate - a caller does not get to
// choose how its own trail reads.
func sanitise(s string) string {
	if s == "" || len(s) > maxInboundLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.'
		if !ok {
			return ""
		}
	}
	return s
}
