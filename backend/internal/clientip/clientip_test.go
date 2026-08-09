package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(t *testing.T, peer, forwarded string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = peer
	if forwarded != "" {
		r.Header.Set(forwardedHeader, forwarded)
	}
	return r
}

func mustNew(t *testing.T, cidrs ...string) *Resolver {
	t.Helper()
	r, err := New(cidrs)
	if err != nil {
		t.Fatalf("New(%v): %v", cidrs, err)
	}
	return r
}

// The finding this package exists for. Rotating X-Forwarded-For used to produce a new
// lockout key per request, so a credential brute force was never blocked: twelve failed
// logins, no block, against six from a fixed source that did block.
func TestSpoofedHeaderCannotChangeTheKeyWithoutATrustedProxy(t *testing.T) {
	r := mustNew(t) // nothing trusted: the default
	first := r.Of(req(t, "203.0.113.9:5555", "198.51.100.1"))
	second := r.Of(req(t, "203.0.113.9:6666", "198.51.100.2"))
	if first != second {
		t.Fatalf("two requests from one host keyed differently (%q vs %q) - rotating the header still evades the lockout", first, second)
	}
	if first != "203.0.113.9" {
		t.Errorf("keyed on %q, want the connecting peer", first)
	}
}

// The other half of the same finding: an attacker who can pick the key can aim it. The
// lockout runs BEFORE authentication, so locking a victim's address rejects their valid
// credentials too - a denial of service against a named third party.
func TestAnAttackerCannotAimTheKeyAtSomeoneElse(t *testing.T) {
	r := mustNew(t)
	got := r.Of(req(t, "203.0.113.9:5555", "10.0.0.7"))
	if got == "10.0.0.7" {
		t.Fatal("the request keyed on an address the client chose - it can lock out anyone it names")
	}
}

// Behind a proxy we DO trust, the real client must come back, or every user shares one
// key and a single attacker locks out everybody at once.
func TestTrustedProxyYieldsTheRealClient(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8")
	got := r.Of(req(t, "10.0.0.5:443", "198.51.100.23"))
	if got != "198.51.100.23" {
		t.Fatalf("keyed on %q, want the client the trusted proxy recorded", got)
	}
}

// The case that makes right-to-left necessary. nginx APPENDS to whatever the client
// sent, so a forged entry sits to the LEFT of the real one. Reading the leftmost entry -
// which is what the old code did - reads the attacker's value even behind a correct proxy.
func TestForgedPrefixBehindATrustedProxyIsIgnored(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8")
	got := r.Of(req(t, "10.0.0.5:443", "1.2.3.4, 198.51.100.23"))
	if got == "1.2.3.4" {
		t.Fatal("took the leftmost hop - a client that sends its own X-Forwarded-For still chooses its key")
	}
	if got != "198.51.100.23" {
		t.Fatalf("keyed on %q, want the address the trusted proxy appended", got)
	}
}

// A chain of trusted hops is walked through to the first one we did not write.
func TestChainOfTrustedProxiesIsWalkedThrough(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8", "192.168.0.0/16")
	got := r.Of(req(t, "10.0.0.5:443", "198.51.100.23, 192.168.1.1, 10.0.0.9"))
	if got != "198.51.100.23" {
		t.Fatalf("keyed on %q, want the first untrusted hop from the right", got)
	}
}

// A header arriving from an untrusted peer is hearsay even if it looks plausible.
func TestHeaderFromAnUntrustedPeerIsIgnored(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8")
	got := r.Of(req(t, "203.0.113.9:5555", "198.51.100.23"))
	if got != "203.0.113.9" {
		t.Fatalf("keyed on %q, want the peer - the request did not come through a trusted proxy", got)
	}
}

// Garbage must not become a key, and must not fall through to something attacker-chosen.
func TestUnparseableHopFallsBackToThePeer(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8")
	got := r.Of(req(t, "10.0.0.5:443", "not-an-ip"))
	if got != "10.0.0.5" {
		t.Fatalf("keyed on %q, want the peer", got)
	}
}

// When every hop is our own infrastructure there is no client address recorded, and
// inventing one would be worse than keying on the proxy.
func TestAllHopsTrustedFallsBackToThePeer(t *testing.T) {
	r := mustNew(t, "10.0.0.0/8")
	got := r.Of(req(t, "10.0.0.5:443", "10.0.0.9, 10.0.0.8"))
	if got != "10.0.0.5" {
		t.Fatalf("keyed on %q, want the peer", got)
	}
}

// The port must not be part of the key: a brute-forcer opens a new connection - and so
// gets a new ephemeral port - for every attempt.
func TestThePortIsNotPartOfTheKey(t *testing.T) {
	r := mustNew(t)
	if a, b := r.Of(req(t, "203.0.113.9:1111", "")), r.Of(req(t, "203.0.113.9:2222", "")); a != b {
		t.Fatalf("%q != %q - each connection would get its own budget", a, b)
	}
}

// A nil Resolver is the safe one, not the permissive one.
func TestNilResolverTrustsNothing(t *testing.T) {
	var r *Resolver
	if got := r.Of(req(t, "203.0.113.9:5555", "10.0.0.7")); got != "203.0.113.9" {
		t.Fatalf("nil resolver keyed on %q, want the peer", got)
	}
}

func TestBareAddressIsAcceptedAsATrustedProxy(t *testing.T) {
	r := mustNew(t, "10.0.0.5")
	if got := r.Of(req(t, "10.0.0.5:443", "198.51.100.23")); got != "198.51.100.23" {
		t.Fatalf("keyed on %q - a bare address should work as a /32", got)
	}
}

// Misconfiguration must be loud: silently ignoring a bad CIDR would leave an operator
// believing their proxy is trusted when it is not.
func TestMalformedTrustedProxyIsRejected(t *testing.T) {
	if _, err := New([]string{"10.0.0.0/8", "definitely-not-a-cidr"}); err == nil {
		t.Fatal("a malformed trusted-proxy entry was accepted")
	}
}

// IPv6 clients must key correctly too, including the IPv4-mapped form a dual-stack
// listener produces.
func TestIPv6(t *testing.T) {
	r := mustNew(t, "2001:db8::/32")
	if got := r.Of(req(t, "[2001:db8::1]:443", "198.51.100.23")); got != "198.51.100.23" {
		t.Fatalf("IPv6 trusted proxy: keyed on %q", got)
	}
	plain := mustNew(t)
	if got := plain.Of(req(t, "[2001:db8::99]:443", "10.0.0.1")); got != "2001:db8::99" {
		t.Fatalf("IPv6 peer: keyed on %q", got)
	}
}
