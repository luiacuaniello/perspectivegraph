package analyzer

import (
	"reflect"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// TestBothBuildersAgree is the guard on the shared assembler. An AttackPath can be
// produced two ways - the in-process Dijkstra (reconstruct) and the database
// pathfinder (attackPathFromRaw) - and before assembleAttackPath existed each one
// carried its own copy of the scoring assembly, so an edit to one could silently
// diverge from the other. This pins them to the same output for the same route.
func TestBothBuildersAgree(t *testing.T) {
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "vm", Label: ontology.LabelVirtualMachine, Name: "app-vm",
				Properties: map[string]any{ontology.PropRuntimeAlert: true}},
			{ID: "cve", Label: ontology.LabelCVE, Name: "CVE-2021-44228",
				Properties: map[string]any{ontology.PropCVSS: 10.0, ontology.PropKEV: true}},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "admin-role",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeExposes, From: "lb", To: "vm", ExploitProbability: 0.9},
			{Type: ontology.EdgeAffects, From: "vm", To: "cve", ExploitProbability: 0.8},
			{Type: ontology.EdgeExploits, From: "cve", To: "role", ExploitProbability: 0.7,
				Properties: map[string]any{ontology.PropWeightBasis: "kev"}},
		},
	}

	viaDijkstra := FindCriticalPaths(snap)
	if len(viaDijkstra) != 1 {
		t.Fatalf("expected 1 path from the in-process pathfinder, got %d", len(viaDijkstra))
	}

	byID := snap.NodeByID()
	viaDB, ok := attackPathFromRaw(graph.RawPath{
		Nodes: []ontology.Node{byID["lb"], byID["vm"], byID["cve"], byID["role"]},
		Edges: snap.Edges,
	})
	if !ok {
		t.Fatal("the database pathfinder rejected a well-formed route")
	}

	if !reflect.DeepEqual(viaDijkstra[0], viaDB) {
		a, b := viaDijkstra[0], viaDB
		t.Errorf("the two builders diverged:\n  dijkstra: id=%s score=%.6f ub=%.6f conf=%.6f post=%.6f mix=%.6f runtime=%v corr=%v\n  database: id=%s score=%.6f ub=%.6f conf=%.6f post=%.6f mix=%.6f runtime=%v corr=%v",
			a.ID, a.Score, a.ScoreUpperBound, a.Confidence, a.PosteriorMean, a.MixtureScore, a.RuntimeConfirmed, a.CorrelatedHops,
			b.ID, b.Score, b.ScoreUpperBound, b.Confidence, b.PosteriorMean, b.MixtureScore, b.RuntimeConfirmed, b.CorrelatedHops)
	}
}

func TestClampProb(t *testing.T) {
	cases := map[float64]float64{0: 0.01, -1: 0.01, 0.5: 0.5, 1: 1, 1.5: 1}
	for in, want := range cases {
		if got := clampProb(in); got != want {
			t.Errorf("clampProb(%v) = %v, want %v", in, got, want)
		}
	}
}
