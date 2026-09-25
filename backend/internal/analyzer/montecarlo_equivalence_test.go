package analyzer

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// randomSnapshot builds a graph with everything the trials must get right: shared weight
// causes, edges to nodes absent from the node list, parallel edges, self-loops, sinks,
// and several seeds and jewels. (A node listed twice is the one case the rewrite answers
// differently, on purpose - see TestANodeListedTwiceCountsOnce.)
func randomSnapshot(r *rand.Rand, n, m int) graph.Snapshot {
	labels := []ontology.Label{ontology.LabelContainer, ontology.LabelCVE, ontology.LabelIAMRole, ontology.LabelLoadBalancer, ontology.LabelDatabase}
	var snap graph.Snapshot
	for i := 0; i < n; i++ {
		props := map[string]any{}
		if r.Intn(6) == 0 {
			props[ontology.PropInternetExposed] = true
		}
		if r.Intn(5) == 0 {
			props[ontology.PropCrownJewel] = true
		}
		snap.Nodes = append(snap.Nodes, ontology.Node{ID: fmt.Sprintf("n%d", i), Label: labels[r.Intn(len(labels))], Name: fmt.Sprintf("node %d", i), Properties: props})
	}
	snap.Nodes[0].Properties[ontology.PropInternetExposed] = true
	causes := []string{"CVE-2026-0001", "CVE-2026-0002", "cred:deploy-key"}
	for i := 0; i < m; i++ {
		from, to := fmt.Sprintf("n%d", r.Intn(n)), fmt.Sprintf("n%d", r.Intn(n+3)) // some point past the node list
		props := map[string]any{}
		if r.Intn(3) == 0 {
			props[ontology.PropWeightCause] = causes[r.Intn(len(causes))]
		}
		snap.Edges = append(snap.Edges, ontology.Edge{Type: ontology.EdgeConnectsTo, From: from, To: to,
			ExploitProbability: r.Float64(), Properties: props})
	}
	return snap
}

// The rewrite on integer indices must reproduce the map-based implementation exactly -
// every field, every jewel, the band and the mixture - for the same graph and seed.
// Anything less would silently move every number the dashboard, the calibration history
// and the gate have ever recorded.
func TestSimulateRiskMatchesTheReferenceBitForBit(t *testing.T) {
	ctx := context.Background()
	r := rand.New(rand.NewSource(20260925))
	snaps := []graph.Snapshot{genLayeredGraph(6, 4, 5, 30, 3, 11)}
	for i := 0; i < 12; i++ {
		snaps = append(snaps, randomSnapshot(r, 20+r.Intn(60), 40+r.Intn(200)))
	}
	for i, snap := range snaps {
		for _, seed := range []uint64{1, 9, 424242} {
			want, err := refSimulateRisk(ctx, snap, 300, seed)
			if err != nil {
				t.Fatal(err)
			}
			got, err := SimulateRisk(ctx, snap, 300, seed)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("graph %d seed %d differs from the reference:\n got  any=%v band=[%v,%v] mix=%v\n want any=%v band=[%v,%v] mix=%v",
					i, seed, got.AnyCompromiseProbability, got.SensitivityLow, got.SensitivityHigh, got.MixtureCompromiseProbability,
					want.AnyCompromiseProbability, want.SensitivityLow, want.SensitivityHigh, want.MixtureCompromiseProbability)
			}
			point, err := SimulateRiskWith(ctx, snap, 300, seed, RiskOptions{PointOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if point.AnyCompromiseProbability != want.AnyCompromiseProbability || !reflect.DeepEqual(point.CrownJewels, want.CrownJewels) {
				t.Fatalf("graph %d seed %d: the point-only run changed the point estimate", i, seed)
			}
		}
	}
}

// A node listed twice in a snapshot - duplicate vertices, as concurrent replicas could
// write before 1.19 - is still one jewel. It used to be counted once per listing: a
// compromise probability of 2 and a NaN interval.
func TestANodeListedTwiceCountsOnce(t *testing.T) {
	jewel := ontology.Node{ID: "db", Label: ontology.LabelDatabase, Name: "db",
		Properties: map[string]any{ontology.PropCrownJewel: true}}
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Properties: map[string]any{ontology.PropInternetExposed: true}},
			jewel, jewel,
		},
		Edges: []ontology.Edge{{Type: ontology.EdgeConnectsTo, From: "lb", To: "db", ExploitProbability: 0.7}},
	}
	sim, err := SimulateRisk(context.Background(), snap, 500, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(sim.CrownJewels) != 1 {
		t.Fatalf("%d jewel entries for one jewel listed twice", len(sim.CrownJewels))
	}
	j := sim.CrownJewels[0]
	if j.CompromiseProbability > 1 || j.CILow != j.CILow || j.CIHigh != j.CIHigh || sim.ExpectedCompromised > 1 {
		t.Errorf("jewel listed twice: %+v, expected compromised %v", j, sim.ExpectedCompromised)
	}
}
