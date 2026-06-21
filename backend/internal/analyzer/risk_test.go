package analyzer

import (
	"math"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Two routes from the internet seed to the crown jewel that share the lb→c1 edge:
//
//	lb --0.9--> c1 --0.5--> cve --0.8--> role   (S = 0.36)
//	lb --0.9--> c1 --0.2-------------->  role   (S = 0.18)
//
// P(role compromised) = P(lb→c1) * [1 - (1-0.2)(1-0.5*0.8)] = 0.9 * 0.52 = 0.468,
// which is strictly greater than the best single path (0.36): the whole point of
// the Monte Carlo union.
func twoRouteSnap() graph.Snapshot {
	return graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "c1", Label: ontology.LabelContainer, Name: "payments"},
			{ID: "cve", Label: ontology.LabelCVE, Name: "CVE-2021-44228"},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "admin",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeExposes, From: "lb", To: "c1", ExploitProbability: 0.9},
			{Type: ontology.EdgeAffects, From: "c1", To: "cve", ExploitProbability: 0.5},
			{Type: ontology.EdgeExploits, From: "cve", To: "role", ExploitProbability: 0.8},
			{Type: ontology.EdgeAssumes, From: "c1", To: "role", ExploitProbability: 0.2},
		},
	}
}

func TestSimulateRiskUnionExceedsBestPath(t *testing.T) {
	sim := SimulateRisk(twoRouteSnap(), 20000, 1)
	if len(sim.CrownJewels) != 1 {
		t.Fatalf("expected 1 crown jewel, got %d", len(sim.CrownJewels))
	}
	got := sim.CrownJewels[0].CompromiseProbability
	if math.Abs(got-0.468) > 0.02 {
		t.Errorf("P(role) = %.4f, want ≈ 0.468", got)
	}
	// The union must exceed the single best path's score (0.36).
	if got <= 0.36 {
		t.Errorf("union probability %.4f should exceed best single path 0.36", got)
	}
	// The estimate must sit within its own reported CI.
	cj := sim.CrownJewels[0]
	if got < cj.CILow || got > cj.CIHigh {
		t.Errorf("point estimate %.4f outside CI [%.4f, %.4f]", got, cj.CILow, cj.CIHigh)
	}
	if math.Abs(sim.AnyCompromiseProbability-got) > 1e-9 {
		t.Errorf("with one jewel, any-compromise (%.4f) should equal its probability (%.4f)", sim.AnyCompromiseProbability, got)
	}
}

func TestSimulateRiskSensitivityBand(t *testing.T) {
	sim := SimulateRisk(twoRouteSnap(), 20000, 1)
	// The band must bracket the nominal estimate (scaling edge p down lowers it,
	// up raises it) and be visibly wide, since the inputs are heuristic here.
	if !(sim.SensitivityLow < sim.AnyCompromiseProbability && sim.AnyCompromiseProbability < sim.SensitivityHigh) {
		t.Errorf("nominal %.3f not bracketed by band [%.3f, %.3f]",
			sim.AnyCompromiseProbability, sim.SensitivityLow, sim.SensitivityHigh)
	}
	if sim.SensitivityHigh-sim.SensitivityLow < 0.2 {
		t.Errorf("expected a wide sensitivity band for heuristic inputs, got [%.3f, %.3f]",
			sim.SensitivityLow, sim.SensitivityHigh)
	}
}

func TestSimulateRiskReproducible(t *testing.T) {
	a := SimulateRisk(twoRouteSnap(), 5000, 42)
	b := SimulateRisk(twoRouteSnap(), 5000, 42)
	if a.AnyCompromiseProbability != b.AnyCompromiseProbability {
		t.Errorf("same seed must be reproducible: %v vs %v", a.AnyCompromiseProbability, b.AnyCompromiseProbability)
	}
}

func TestKShortestPathsEnumeratesBothRoutes(t *testing.T) {
	paths := KShortestPaths(twoRouteSnap(), "lb", "role", 5)
	if len(paths) != 2 {
		t.Fatalf("expected 2 loopless paths, got %d", len(paths))
	}
	if math.Abs(paths[0].Score-0.36) > 1e-9 {
		t.Errorf("best path score = %.4f, want 0.36", paths[0].Score)
	}
	if math.Abs(paths[1].Score-0.18) > 1e-9 {
		t.Errorf("second path score = %.4f, want 0.18", paths[1].Score)
	}
	if paths[0].ID == paths[1].ID {
		t.Error("the two paths must have distinct IDs")
	}
}

func TestWhatIfCuttingExploitEdgeLowersRisk(t *testing.T) {
	snap := twoRouteSnap()
	cuts := []EdgeCut{{From: "cve", To: "role", Type: ontology.EdgeExploits}}
	r := WhatIf(snap, cuts, 20000, 7)

	if r.RemovedEdges != 1 {
		t.Fatalf("expected 1 edge removed, got %d", r.RemovedEdges)
	}
	if len(r.Before) != 1 || len(r.After) != 1 {
		t.Fatalf("expected one path before and after, got %d / %d", len(r.Before), len(r.After))
	}
	// After the cut only the weak direct route (0.18) survives.
	if math.Abs(r.After[0].Score-0.18) > 1e-9 {
		t.Errorf("surviving path score = %.4f, want 0.18", r.After[0].Score)
	}
	// Quantified risk must drop, toward 0.9*0.2 = 0.18.
	if r.RiskReduction() <= 0 {
		t.Errorf("expected positive risk reduction, got %.4f", r.RiskReduction())
	}
	if math.Abs(r.AfterRisk.AnyCompromiseProbability-0.18) > 0.02 {
		t.Errorf("post-cut risk = %.4f, want ≈ 0.18", r.AfterRisk.AnyCompromiseProbability)
	}
}
