package api

import (
	"context"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// B1: an app-scoped principal only sees the graph (and, by the same funnel, the
// paths/exports/search) for its allowed applications.
func TestAppScopingFiltersSnapshot(t *testing.T) {
	a, _ := testAPI(t)
	ctx := context.Background()
	store, err := a.manager.For(ctx, auth.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	// Two independent apps: payments (lb-pay → pay-db) and web (lb-web → web-db).
	nodes := []ontology.Node{
		{ID: "lb-pay", Label: ontology.LabelLoadBalancer, Name: "alb-pay", Properties: map[string]any{ontology.PropRepoSlug: "payments"}},
		{ID: "pay-db", Label: ontology.LabelDatabase, Name: "payments-db", Properties: map[string]any{ontology.PropRepoSlug: "payments"}},
		{ID: "lb-web", Label: ontology.LabelLoadBalancer, Name: "alb-web", Properties: map[string]any{"app": "web"}},
		{ID: "web-db", Label: ontology.LabelDatabase, Name: "web-db", Properties: map[string]any{"app": "web"}},
	}
	for _, n := range nodes {
		if err := store.UpsertNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []ontology.Edge{
		{Type: ontology.EdgeExposes, From: "lb-pay", To: "pay-db", ExploitProbability: 0.9},
		{Type: ontology.EdgeExposes, From: "lb-web", To: "web-db", ExploitProbability: 0.9},
	} {
		if err := store.UpsertEdge(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	// Unscoped principal sees both apps' 4 nodes.
	full, err := a.snapshot(auth.WithPrincipal(ctx, auth.Principal{Tenant: auth.DefaultTenant}))
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Nodes) != 4 {
		t.Fatalf("unscoped snapshot = %d nodes, want 4", len(full.Nodes))
	}

	// Scoped to "payments" → only the 2 payments nodes; the web app is invisible.
	scoped, err := a.snapshot(auth.WithPrincipal(ctx, auth.Principal{Tenant: auth.DefaultTenant, Apps: []string{"payments"}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped.Nodes) != 2 {
		t.Fatalf("payments-scoped snapshot = %d nodes, want 2", len(scoped.Nodes))
	}
	for _, n := range scoped.Nodes {
		if n.ID == "lb-web" || n.ID == "web-db" {
			t.Errorf("scoped snapshot leaked a web-app node: %s", n.ID)
		}
	}
}

func TestPathMatchesAnyApp(t *testing.T) {
	path := analyzer.AttackPath{Nodes: []ontology.Node{
		{ID: "x", Properties: map[string]any{ontology.PropRepoSlug: "payments"}},
		{ID: "y", Properties: map[string]any{"app": "shared"}},
	}}
	if !pathMatchesAnyApp(path, []string{"web", "payments"}) {
		t.Error("path touching payments should match the allowlist")
	}
	if pathMatchesAnyApp(path, []string{"billing"}) {
		t.Error("path not touching billing should not match")
	}
	// Empty allowlist is handled by callers (unrestricted), not here.
}
