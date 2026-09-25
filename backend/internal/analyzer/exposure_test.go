package analyzer

import (
	"context"
	"math"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Where attacks start, and what counts as a crown jewel compromised. Three engines used
// to answer the first question differently, and the risk simulation answered the second
// one wrongly for any jewel that was itself exposed.

func exposureNode(id string, label ontology.Label, props map[string]any) ontology.Node {
	return ontology.Node{ID: id, Label: label, Name: id, Properties: props}
}

// Under the credential-origin lens (SEED_IAM_USERS) the path list found the route from a
// leaked identity, while the risk simulation reported 0% and the alternative routes none:
// both started from internet-exposed nodes only, and so did the database path finder.
func TestACredentialOriginSeedIsASeedEverywhere(t *testing.T) {
	ctx := context.Background()
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			exposureNode("User:alice", ontology.LabelUser, map[string]any{ontology.PropCredentialExposed: true}),
			exposureNode("IAM_Role:ops", ontology.LabelIAMRole, nil),
			exposureNode("Bucket:ledger", ontology.LabelBucket, map[string]any{ontology.PropCrownJewel: true}),
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeAssumes, From: "User:alice", To: "IAM_Role:ops", ExploitProbability: 0.9},
			{Type: ontology.EdgeHasPermission, From: "IAM_Role:ops", To: "Bucket:ledger", ExploitProbability: 0.9},
		},
	}
	if n := len(FindCriticalPaths(snap)); n != 1 {
		t.Fatalf("path list: %d paths, want 1", n)
	}
	sim, err := SimulateRisk(ctx, snap, 20000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(sim.AnyCompromiseProbability-0.81) > 0.02 {
		t.Errorf("risk simulation: %.3f, want ≈ 0.81 - the leaked identity must be where it starts", sim.AnyCompromiseProbability)
	}
	alt, err := KShortestToTarget(ctx, snap, "", "Bucket:ledger", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(alt) != 1 {
		t.Errorf("alternative routes: %d, want 1", len(alt))
	}
}

// Reachable is not compromised: an internet-facing database behind a password counts
// only when an edge reaches it. Open to anyone is: a bucket anyone may read is
// compromised in every trial, and the path list shows it as a direct-access path so the
// list and the number agree.
func TestAnExposedJewelIsCompromisedOnlyWhenHeld(t *testing.T) {
	ctx := context.Background()
	reachable := exposureNode("Database:orders", ontology.LabelDatabase, map[string]any{
		ontology.PropInternetExposed: true, ontology.PropCrownJewel: true})
	open := exposureNode("Bucket:exports", ontology.LabelBucket, map[string]any{
		ontology.PropInternetExposed: true, ontology.PropPublicAccess: true, ontology.PropCrownJewel: true})

	// Alone, the reachable one is not compromised and has no path.
	snap := graph.Snapshot{Nodes: []ontology.Node{reachable}}
	if paths := FindCriticalPaths(snap); len(paths) != 0 {
		t.Errorf("a merely reachable jewel got %d paths", len(paths))
	}
	sim, err := SimulateRisk(ctx, snap, 2000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sim.AnyCompromiseProbability != 0 {
		t.Errorf("a merely reachable jewel is %.3f compromised with no edge to it, want 0", sim.AnyCompromiseProbability)
	}

	// An edge from another seed compromises it, at that edge's probability.
	snap.Nodes = append(snap.Nodes, exposureNode("LoadBalancer:edge", ontology.LabelLoadBalancer, map[string]any{ontology.PropInternetExposed: true}))
	snap.Edges = []ontology.Edge{{Type: ontology.EdgeRoutesTo, From: "LoadBalancer:edge", To: "Database:orders", ExploitProbability: 0.4}}
	sim, err = SimulateRisk(ctx, snap, 20000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(sim.AnyCompromiseProbability-0.4) > 0.02 {
		t.Errorf("reached over a 0.4 edge: %.3f, want ≈ 0.4", sim.AnyCompromiseProbability)
	}
	if paths := FindCriticalPaths(snap); len(paths) != 1 || paths[0].DirectAccess {
		t.Errorf("reached over an edge: want one ordinary path, got %+v", paths)
	}

	// The open one is compromised in every trial and has a direct-access path.
	snap = graph.Snapshot{Nodes: []ontology.Node{open}}
	sim, err = SimulateRisk(ctx, snap, 2000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sim.AnyCompromiseProbability != 1 {
		t.Errorf("a jewel open to anyone is %.3f compromised, want 1", sim.AnyCompromiseProbability)
	}
	paths := FindCriticalPaths(snap)
	if len(paths) != 1 {
		t.Fatalf("a jewel open to anyone: %d paths, want its direct-access path", len(paths))
	}
	p := paths[0]
	if !p.DirectAccess || p.Score != 1 || len(p.Steps) != 0 || len(p.Nodes) != 1 || p.Target().ID != open.ID {
		t.Errorf("direct-access path: %+v", p)
	}
	if p.MixtureScore != 1 || p.PosteriorMean != 1 || p.ScoreCILow != 1 || p.ScoreCIHigh != 1 || p.ScoreUpperBound != 1 {
		t.Errorf("a certain path must read certain in every lens: mixture %v posterior %v [%v, %v] ceiling %v",
			p.MixtureScore, p.PosteriorMean, p.ScoreCILow, p.ScoreCIHigh, p.ScoreUpperBound)
	}
	Prioritize(paths)
	if paths[0].PriorityLabel != "P1" {
		t.Errorf("a sensitive asset open to anyone is %s (%.1f), want P1: it is not a prediction, it is readable now",
			paths[0].PriorityLabel, paths[0].Priority)
	}
}

// With one jewel compromised in every trial, P(any jewel) is pinned at 1 and a cut that
// closes every route to another jewel moves it by nothing. The expected number of jewels
// compromised still moves, and that is what a fix is proven on.
func TestExpectedReductionSeesPastASaturatedHeadline(t *testing.T) {
	ctx := context.Background()
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			exposureNode("LoadBalancer:edge", ontology.LabelLoadBalancer, map[string]any{ontology.PropInternetExposed: true}),
			exposureNode("VirtualMachine:app", ontology.LabelVirtualMachine, nil),
			exposureNode("Database:orders", ontology.LabelDatabase, map[string]any{ontology.PropCrownJewel: true}),
			exposureNode("Bucket:exports", ontology.LabelBucket, map[string]any{
				ontology.PropInternetExposed: true, ontology.PropPublicAccess: true, ontology.PropCrownJewel: true}),
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeRoutesTo, From: "LoadBalancer:edge", To: "VirtualMachine:app", ExploitProbability: 0.7},
			{Type: ontology.EdgeConnectsTo, From: "VirtualMachine:app", To: "Database:orders", ExploitProbability: 0.7},
		},
	}
	res, err := WhatIf(ctx, snap, []EdgeCut{{From: "VirtualMachine:app", To: "Database:orders"}}, 4000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.BeforeRisk.AnyCompromiseProbability != 1 || res.RiskReduction() != 0 {
		t.Fatalf("setup: any before %.3f, reduction %.3f - want the saturated 1 and 0", res.BeforeRisk.AnyCompromiseProbability, res.RiskReduction())
	}
	if math.Abs(res.ExpectedReduction()-0.49) > 0.03 {
		t.Errorf("expected reduction %.3f, want ≈ 0.49 (the orders database's whole risk)", res.ExpectedReduction())
	}
}

// The regression the common random numbers fix: a cut on an edge that leads nowhere has
// no effect, and must read as none - every seed, exactly. With two independent samples it
// read as a reduction about half the time, and a fix's verification believed it.
func TestADeadEndCutReducesNothing(t *testing.T) {
	ctx := context.Background()
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			exposureNode("LoadBalancer:a", ontology.LabelLoadBalancer, map[string]any{ontology.PropInternetExposed: true}),
			exposureNode("VirtualMachine:x", ontology.LabelVirtualMachine, nil),
			exposureNode("VirtualMachine:y", ontology.LabelVirtualMachine, nil),
			exposureNode("VirtualMachine:m", ontology.LabelVirtualMachine, nil),
			exposureNode("Database:j", ontology.LabelDatabase, map[string]any{ontology.PropCrownJewel: true}),
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeConnectsTo, From: "LoadBalancer:a", To: "VirtualMachine:x", ExploitProbability: 0.9},
			{Type: ontology.EdgeConnectsTo, From: "VirtualMachine:x", To: "VirtualMachine:y", ExploitProbability: 0.9},
			{Type: ontology.EdgeConnectsTo, From: "LoadBalancer:a", To: "VirtualMachine:m", ExploitProbability: 0.7},
			{Type: ontology.EdgeConnectsTo, From: "VirtualMachine:m", To: "Database:j", ExploitProbability: 0.7},
		},
	}
	point := RiskOptions{PointOnly: true}
	for seed := uint64(1); seed <= 200; seed++ {
		before, err := SimulateRiskWith(ctx, snap, 800, seed, point)
		if err != nil {
			t.Fatal(err)
		}
		res, err := WhatIfFromWith(ctx, snap, before, []EdgeCut{{From: "LoadBalancer:a", To: "VirtualMachine:x"}}, 800, seed, point)
		if err != nil {
			t.Fatal(err)
		}
		if res.RiskReduction() != 0 || res.ExpectedReduction() != 0 {
			t.Fatalf("seed %d: a dead-end cut reduced the risk by %.4f (expected %.4f)", seed, res.RiskReduction(), res.ExpectedReduction())
		}
	}
}

// Two hops resting on the same weakness stand or fall together. The risk simulation
// always coupled them; the path score multiplied them as if independent, so the same
// two-hop route read 25% in the path list and 50% in the simulation.
func TestAPathOnOneCauseScoresLikeTheSimulation(t *testing.T) {
	cause := map[string]any{ontology.PropWeightCause: "CVE-2024-0001"}
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			exposureNode("LoadBalancer:a", ontology.LabelLoadBalancer, map[string]any{ontology.PropInternetExposed: true}),
			exposureNode("VirtualMachine:m", ontology.LabelVirtualMachine, nil),
			exposureNode("Database:j", ontology.LabelDatabase, map[string]any{ontology.PropCrownJewel: true}),
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeConnectsTo, From: "LoadBalancer:a", To: "VirtualMachine:m", ExploitProbability: 0.5, Properties: cause},
			{Type: ontology.EdgeConnectsTo, From: "VirtualMachine:m", To: "Database:j", ExploitProbability: 0.6, Properties: cause},
		},
	}
	paths := FindCriticalPaths(snap)
	if len(paths) != 1 {
		t.Fatalf("%d paths", len(paths))
	}
	p := paths[0]
	if p.Score != 0.5 {
		t.Errorf("score %.3f, want 0.5: one cause, counted once at its weakest hop", p.Score)
	}
	if !p.CorrelatedHops {
		t.Error("two hops on one declared cause must read as correlated")
	}
	if p.MixtureScore < p.Score-1e-12 || p.MixtureScore > p.ScoreUpperBound+1e-12 {
		t.Errorf("mixture %.4f outside [%.4f, %.4f]", p.MixtureScore, p.Score, p.ScoreUpperBound)
	}
	sim, err := SimulateRisk(context.Background(), snap, 20000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(sim.AnyCompromiseProbability-p.Score) > 0.02 {
		t.Errorf("simulation %.3f, path %.3f: one route, one number", sim.AnyCompromiseProbability, p.Score)
	}
}

// An alternative route is the same kind of object as a critical path: the same route
// must read the same in both lists. It used to come back without its interval, its
// mixture and its upper bound.
func TestAnAlternativeRouteIsScoredLikeACriticalPath(t *testing.T) {
	snap := twoRouteSnap()
	crit := FindCriticalPaths(snap)
	alt, err := KShortestPaths(context.Background(), snap, "lb", "role", 1)
	if err != nil || len(crit) != 1 || len(alt) != 1 {
		t.Fatalf("paths: %d critical, %d alternative, err %v", len(crit), len(alt), err)
	}
	a, c := alt[0], crit[0]
	if a.ID != c.ID || a.Score != c.Score || a.ScoreCILow != c.ScoreCILow || a.ScoreCIHigh != c.ScoreCIHigh ||
		a.MixtureScore != c.MixtureScore || a.ScoreUpperBound != c.ScoreUpperBound || a.PosteriorMean != c.PosteriorMean {
		t.Errorf("the same route reads differently:\n alternative %+v\n critical    %+v", a, c)
	}
}
