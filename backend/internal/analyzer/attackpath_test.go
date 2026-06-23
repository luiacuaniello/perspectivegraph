package analyzer

import (
	"math"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Graph under test:
//
//	(LB, internet)  --EXPOSES p=0.9-->  (Container)
//	(Container)     --AFFECTS p=0.5-->  (CVE)
//	(CVE)           --EXPLOITS p=0.8-->  (Role, crown jewel)
//	(Container)     --ASSUMES p=0.2-->  (Role)          // a weaker direct route
//
// Best path LB→Container→CVE→Role:  0.9 * 0.5 * 0.8 = 0.36
// Direct   LB→Container→Role:       0.9 * 0.2       = 0.18
// Dijkstra over -ln(p) must pick the 0.36 route.
func TestFindCriticalPaths(t *testing.T) {
	snap := graph.Snapshot{
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

	paths := FindCriticalPaths(snap)
	if len(paths) != 1 {
		t.Fatalf("expected 1 critical path, got %d", len(paths))
	}

	best := paths[0]
	if got, want := best.Score, 0.36; math.Abs(got-want) > 1e-9 {
		t.Errorf("score = %v, want %v", got, want)
	}
	if best.Source().ID != "lb" || best.Target().ID != "role" {
		t.Errorf("path endpoints = %s..%s, want lb..role", best.Source().ID, best.Target().ID)
	}
	wantNodes := []string{"lb", "c1", "cve", "role"}
	if len(best.Nodes) != len(wantNodes) {
		t.Fatalf("path length = %d, want %d", len(best.Nodes), len(wantNodes))
	}
	for i, id := range wantNodes {
		if best.Nodes[i].ID != id {
			t.Errorf("node[%d] = %s, want %s", i, best.Nodes[i].ID, id)
		}
	}
}

// TestScoreBandAndCorrelation pins the C1 independence honesty: the headline
// Score is the product (independence), ScoreUpperBound is the weakest hop (the
// shared-cause / comonotonic bound), and CorrelatedHops flags when two hops rest
// on the same weight basis.
func TestScoreBandAndCorrelation(t *testing.T) {
	jewel := map[string]any{ontology.PropCrownJewel: true}
	internet := map[string]any{ontology.PropInternetExposed: true}

	t.Run("correlated heuristic hops", func(t *testing.T) {
		// Two hops, both topology defaults → basis "heuristic" twice → correlated.
		// Score = 0.9*0.4 = 0.36; ScoreUpperBound = min(0.9,0.4) = 0.4.
		snap := graph.Snapshot{
			Nodes: []ontology.Node{
				{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb", Properties: internet},
				{ID: "c1", Label: ontology.LabelContainer, Name: "payments"},
				{ID: "role", Label: ontology.LabelIAMRole, Name: "admin", Properties: jewel},
			},
			Edges: []ontology.Edge{
				{Type: ontology.EdgeExposes, From: "lb", To: "c1", ExploitProbability: 0.9},
				{Type: ontology.EdgeAssumes, From: "c1", To: "role", ExploitProbability: 0.4},
			},
		}
		p := onlyPath(t, snap)
		if math.Abs(p.Score-0.36) > 1e-9 {
			t.Errorf("score = %v, want 0.36 (product)", p.Score)
		}
		if math.Abs(p.ScoreUpperBound-0.4) > 1e-9 {
			t.Errorf("scoreUpperBound = %v, want 0.4 (weakest hop)", p.ScoreUpperBound)
		}
		if p.ScoreUpperBound < p.Score {
			t.Errorf("upper bound %v < score %v - band inverted", p.ScoreUpperBound, p.Score)
		}
		if !p.CorrelatedHops {
			t.Errorf("expected correlatedHops=true for two heuristic hops")
		}
	})

	t.Run("distinct bases not correlated", func(t *testing.T) {
		// EXPOSES → heuristic, AFFECTS onto a CVSS-anchored CVE → cvss. Distinct
		// bases → not flagged.
		snap := graph.Snapshot{
			Nodes: []ontology.Node{
				{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb", Properties: internet},
				{ID: "c1", Label: ontology.LabelContainer, Name: "payments"},
				{ID: "cve", Label: ontology.LabelCVE, Name: "CVE-2024-0001",
					Properties: map[string]any{ontology.PropCVSS: 9.1, ontology.PropCrownJewel: true}},
			},
			Edges: []ontology.Edge{
				{Type: ontology.EdgeExposes, From: "lb", To: "c1", ExploitProbability: 0.8},
				{Type: ontology.EdgeAffects, From: "c1", To: "cve", ExploitProbability: 0.6},
			},
		}
		p := onlyPath(t, snap)
		if p.CorrelatedHops {
			t.Errorf("expected correlatedHops=false for distinct bases")
		}
	})

	t.Run("single hop collapses the band", func(t *testing.T) {
		snap := graph.Snapshot{
			Nodes: []ontology.Node{
				{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb", Properties: internet},
				{ID: "role", Label: ontology.LabelIAMRole, Name: "admin", Properties: jewel},
			},
			Edges: []ontology.Edge{
				{Type: ontology.EdgeExposes, From: "lb", To: "role", ExploitProbability: 0.7},
			},
		}
		p := onlyPath(t, snap)
		if math.Abs(p.ScoreUpperBound-p.Score) > 1e-9 {
			t.Errorf("single-hop band should collapse: score=%v upper=%v", p.Score, p.ScoreUpperBound)
		}
		if p.CorrelatedHops {
			t.Errorf("a single hop cannot be correlated")
		}
	})
}

func onlyPath(t *testing.T, snap graph.Snapshot) AttackPath {
	t.Helper()
	paths := FindCriticalPaths(snap)
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	return paths[0]
}

func TestNoPathWhenUnreachable(t *testing.T) {
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer,
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "db", Label: ontology.LabelVirtualMachine,
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		// no edges connecting them
	}
	if paths := FindCriticalPaths(snap); len(paths) != 0 {
		t.Fatalf("expected 0 paths, got %d", len(paths))
	}
}
