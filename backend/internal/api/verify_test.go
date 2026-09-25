package api

import (
	"context"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/remediation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A fix's "verified" is a claim the dashboard and the MCP tools pass on: this fix has
// been simulated and it helps. It used to be granted when two independent 800-trial
// simulations differed by more than 0.05 points - noise of ±2.5 points - so a fix that
// cut an edge leading nowhere was "verified" about half the time, including with the
// seed the resolver uses. Both simulations now run the same trials, and a cut that
// protects nothing reduces nothing.
func TestAFixThatProtectsNothingIsNotVerified(t *testing.T) {
	a := seededAPI(t)
	ctx := context.Background()
	store, err := a.manager.For(ctx, graph.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	// A dead end off the internet entry: lb → billing, and billing reaches nothing.
	if err := store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeRoutesTo, From: "lb", To: "billing", ExploitProbability: 0.9}); err != nil {
		t.Fatal(err)
	}
	v, err := a.verifyCut(viewerCtx(), remediation.CutEdge{From: "lb", To: "billing", Type: string(ontology.EdgeRoutesTo)})
	if err != nil {
		t.Fatal(err)
	}
	got := v.(map[string]any)
	if got["removedEdges"] != 1 {
		t.Fatalf("the cut did not match the edge: %+v", got)
	}
	if got["verified"] != false || got["expectedReduction"] != 0.0 || got["riskReductionPct"] != 0.0 {
		t.Errorf("a cut that protects nothing: %+v - want verified false and both reductions exactly 0", got)
	}

	// The cut that does protect the jewel is verified.
	v, err = a.verifyCut(viewerCtx(), remediation.CutEdge{From: "svc", To: "role", Type: string(ontology.EdgeExposes)})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(map[string]any); got["verified"] != true {
		t.Errorf("cutting the only route to the jewel: %+v - want verified", got)
	}
}
