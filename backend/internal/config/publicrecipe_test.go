package config

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
)

// The published compose recipe is the one deployment with a proxy ALWAYS in front of the
// backend - the dashboard's nginx - so it trusts that proxy by default. Without it the
// per-IP controls key on nginx and become global, which is what
// api.TestAPublishedInstanceKeepsVisitorsApartBehindItsProxy pins.
//
// The default is only right if it covers the networks Docker really hands a compose project
// and stays narrow enough that a peer on the internet is never believed.
func TestPublishedRecipeTrustsTheDashboardProxy(t *testing.T) {
	public := mustRead(t, repoRoot(t), "docker-compose.public.yml")
	m := regexp.MustCompile(`(?m)^\s+TRUSTED_PROXY_CIDRS:\s*\$\{TRUSTED_PROXY_CIDRS:-([^}]+)\}`).FindStringSubmatch(public)
	if m == nil {
		t.Fatal("docker-compose.public.yml must set TRUSTED_PROXY_CIDRS with a default: every visitor reaches the backend through the dashboard's nginx")
	}
	ips, err := clientip.New(strings.Split(m[1], ","))
	if err != nil {
		t.Fatalf("the recipe's default does not parse: %v", err)
	}

	// docker0 is 172.17.0.0/16; compose networks take the next /16s, up to 172.31.
	for _, network := range []string{"172.17", "172.18", "172.24", "172.31"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = network + ".0.5:40000"
		// A forged entry first, then the real client as the host's TLS proxy wrote it, then
		// the hop nginx appended.
		r.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9, "+network+".0.1")
		if got := ips.Of(r); got != "203.0.113.9" {
			t.Errorf("behind nginx on %s.0.0/16 the key is %q, want the real client 203.0.113.9", network, got)
		}
	}

	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "203.0.113.50:40000"
	direct.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := ips.Of(direct); got != "203.0.113.50" {
		t.Errorf("a peer on the internet had its header believed (key %q): the default is too wide", got)
	}
}
