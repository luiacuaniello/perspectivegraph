package api

import (
	"context"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// TestTenantIsolation is the load-bearing security proof for a multi-tenant SaaS
// that is, literally, a map of how to attack each customer: a principal scoped to
// one tenant must NEVER see another tenant's graph or attack paths. Every API
// read funnels through a.snapshot(tenantOf(ctx)) / manager.For(tenant), so this
// pins that funnel; a regression that drops the tenant key fails here.
func TestTenantIsolation(t *testing.T) {
	a, _ := testAPI(t)
	ctx := context.Background()

	// Each tenant gets an identical-shaped but distinctly-named internet→jewel path.
	seed := func(tenant, prefix, jewel string) {
		store, err := a.manager.For(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		must := func(e error) {
			if e != nil {
				t.Fatal(e)
			}
		}
		must(store.UpsertNode(ctx, ontology.Node{ID: prefix + "-lb", Label: ontology.LabelLoadBalancer, Name: prefix + "-alb",
			Properties: map[string]any{ontology.PropInternetExposed: true}}))
		must(store.UpsertNode(ctx, ontology.Node{ID: prefix + "-jewel", Label: ontology.LabelDatabase, Name: jewel,
			Properties: map[string]any{ontology.PropCrownJewel: true}}))
		must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: prefix + "-lb", To: prefix + "-jewel", ExploitProbability: 0.9}))
	}
	seed("acme", "acme", "acme-secrets")
	seed("globex", "globex", "globex-secrets")

	snapFor := func(tenant string) []ontology.Node {
		snap, err := a.snapshot(auth.WithPrincipal(ctx, auth.Principal{Tenant: tenant}))
		if err != nil {
			t.Fatalf("snapshot(%s): %v", tenant, err)
		}
		return snap.Nodes
	}
	has := func(nodes []ontology.Node, id string) bool {
		for _, n := range nodes {
			if n.ID == id {
				return true
			}
		}
		return false
	}

	acme := snapFor("acme")
	if !has(acme, "acme-jewel") {
		t.Error("acme cannot see its own jewel")
	}
	if has(acme, "globex-jewel") || has(acme, "globex-lb") {
		t.Error("ISOLATION BREACH: acme can see globex's data")
	}

	globex := snapFor("globex")
	if !has(globex, "globex-jewel") {
		t.Error("globex cannot see its own jewel")
	}
	if has(globex, "acme-jewel") || has(globex, "acme-lb") {
		t.Error("ISOLATION BREACH: globex can see acme's data")
	}

	// Attack paths computed from each isolated snapshot stay within the tenant.
	acmePaths := analyzer.FindCriticalPaths(mustSnap(t, a, "acme"))
	globexPaths := analyzer.FindCriticalPaths(mustSnap(t, a, "globex"))
	if len(acmePaths) != 1 || acmePaths[0].Target().Name != "acme-secrets" {
		t.Errorf("acme paths leaked or wrong: %+v", acmePaths)
	}
	if len(globexPaths) != 1 || globexPaths[0].Target().Name != "globex-secrets" {
		t.Errorf("globex paths leaked or wrong: %+v", globexPaths)
	}

	// A named tenant's data must not bleed into the default tenant either.
	def := snapFor("")
	if has(def, "acme-jewel") || has(def, "globex-jewel") {
		t.Error("ISOLATION BREACH: the default tenant sees a named tenant's data")
	}

	// Tenant scoping is case/format-insensitive (NormalizeTenant), so "ACME" is acme.
	if up := snapFor("ACME"); !has(up, "acme-jewel") || has(up, "globex-jewel") {
		t.Error("tenant id normalization broke isolation")
	}
}

func mustSnap(t *testing.T, a *API, tenant string) graph.Snapshot {
	t.Helper()
	s, err := a.snapshot(auth.WithPrincipal(context.Background(), auth.Principal{Tenant: tenant}))
	if err != nil {
		t.Fatalf("snapshot(%s): %v", tenant, err)
	}
	return s
}
