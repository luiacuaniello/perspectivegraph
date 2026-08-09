// Package clientip decides which address a per-IP security control keys on.
//
// It exists because the two controls that key on an address used to disagree. The rate
// limiter took the connecting peer and documented X-Forwarded-For as spoofable; the
// brute-force lockout took the first entry of that same header, unconditionally. The
// weaker of the two guarded the credential door, and the consequence was demonstrable:
// rotating the header defeated the lockout entirely (twelve failed logins, no block,
// where six from a fixed source blocked), and setting it to somebody else's address
// locked THEM out instead - the lockout is checked before authentication, so it rejects
// the victim's valid tokens too.
//
// Neither naive rule is right on its own:
//
//   - Peer only: behind a reverse proxy every request appears to come from the proxy, so
//     one attacker's failures trip the lockout for all users at once.
//   - Header only: any client can write any header, so both the bypass and the targeted
//     lockout above are free.
//
// So trust is explicit. With no configured proxies the peer is used and the header is
// ignored, which is safe by default. With proxies configured, the header is read ONLY
// when the peer is one of them, and is then walked from the right - discarding the hops
// we trust and stopping at the first address we do not. An attacker can prepend entries,
// but prepended entries are to the LEFT of the proxy's own append, so they are never
// what this returns.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// forwardedHeader is the de-facto standard hop list, appended to by each proxy.
const forwardedHeader = "X-Forwarded-For"

// Resolver maps a request to the address per-IP decisions key on. The zero value is
// usable and trusts nothing, so a caller that forgets to configure it gets the safe
// behaviour rather than the spoofable one.
type Resolver struct {
	trusted []netip.Prefix
}

// New builds a Resolver trusting the given CIDRs (or bare addresses). An empty list
// means "no proxy in front": the peer is used and the header is ignored.
func New(cidrs []string) (*Resolver, error) {
	r := &Resolver{}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			r.trusted = append(r.trusted, p)
			continue
		}
		// A bare address is the same thing with a full-length mask - the natural way
		// to write "the one ingress in front of me".
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("clientip: %q is neither a CIDR nor an address", raw)
		}
		r.trusted = append(r.trusted, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return r, nil
}

// TrustsAny reports whether any proxy is trusted, so a caller can log which mode it is in.
func (r *Resolver) TrustsAny() bool { return r != nil && len(r.trusted) > 0 }

// Of returns the address to key on. Nil-safe: a nil Resolver trusts nothing.
func (r *Resolver) Of(req *http.Request) string {
	peer := peerHost(req)
	if r == nil || len(r.trusted) == 0 {
		return peer
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || !r.isTrusted(addr) {
		// The request did not arrive through a proxy we trust, so whatever it claims
		// about earlier hops is hearsay.
		return peer
	}
	hops := req.Header.Get(forwardedHeader)
	if hops == "" {
		return peer
	}
	// Right to left: the rightmost entries were written by infrastructure we trust,
	// anything further left could have been sent by the client.
	parts := strings.Split(hops, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			// An unparseable hop is where the trustworthy part of the list ends: we
			// cannot tell whether what lies beyond it is a proxy or a forgery.
			return peer
		}
		if !r.isTrusted(hop) {
			return hop.String()
		}
	}
	// Every hop is a trusted proxy - no client address was ever recorded.
	return peer
}

func (r *Resolver) isTrusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// peerHost is the connecting address without its port, so a client rotating
// connections - each a new ephemeral port - is still one host.
func peerHost(req *http.Request) string {
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}
