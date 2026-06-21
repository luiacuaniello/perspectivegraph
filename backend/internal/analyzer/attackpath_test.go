package analyzer

import (
	"math"
	"testing"

	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
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
