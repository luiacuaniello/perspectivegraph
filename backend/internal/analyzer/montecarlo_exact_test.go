package analyzer

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The Monte Carlo is held to the exact answer. On a graph small enough to enumerate every
// world - every combination of edges present and absent - the probability that a jewel is
// compromised is a finite sum, and the simulation must land within its sampling error of
// it. This replaced a test that held the engine bit for bit to its previous version: that
// proved a refactor changed nothing, and could say nothing about whether either version
// was right. It could not survive a deliberate change to the sampling either.

// randomSnapshot builds a graph with everything the trials must get right: shared weight
// causes, edges to nodes absent from the node list, parallel and duplicate edges,
// self-loops, sinks, several seeds and jewels, jewels that are seeds themselves - some
// open to anyone, some merely reachable - and credential-origin seeds.
func randomSnapshot(r *rand.Rand, n, m int) graph.Snapshot {
	labels := []ontology.Label{ontology.LabelContainer, ontology.LabelCVE, ontology.LabelIAMRole, ontology.LabelLoadBalancer, ontology.LabelDatabase}
	var snap graph.Snapshot
	for i := 0; i < n; i++ {
		props := map[string]any{}
		switch r.Intn(8) {
		case 0, 1:
			props[ontology.PropInternetExposed] = true
		case 2:
			props[ontology.PropCredentialExposed] = true
		case 3:
			props[ontology.PropInternetExposed] = true
			props[ontology.PropPublicAccess] = true
		}
		if r.Intn(4) == 0 {
			props[ontology.PropCrownJewel] = true
		}
		snap.Nodes = append(snap.Nodes, ontology.Node{ID: fmt.Sprintf("n%d", i), Label: labels[r.Intn(len(labels))], Name: fmt.Sprintf("node %d", i), Properties: props})
	}
	snap.Nodes[0].Properties[ontology.PropInternetExposed] = true
	causes := []string{"CVE-2026-0001", "CVE-2026-0002", "cred:deploy-key"}
	types := []ontology.EdgeType{ontology.EdgeConnectsTo, ontology.EdgeAssumes}
	for i := 0; i < m; i++ {
		from, to := fmt.Sprintf("n%d", r.Intn(n)), fmt.Sprintf("n%d", r.Intn(n+2)) // some point past the node list
		props := map[string]any{}
		if r.Intn(4) == 0 {
			props[ontology.PropWeightCause] = causes[r.Intn(len(causes))]
		}
		snap.Edges = append(snap.Edges, ontology.Edge{Type: types[r.Intn(len(types))], From: from, To: to,
			ExploitProbability: 0.05 + 0.9*r.Float64(), Properties: props})
	}
	return snap
}

// exactRisk enumerates every world of a small snapshot and returns P(any jewel
// compromised) and each jewel's probability, for the edge probabilities prob (indexed
// like snap.Edges). Edges that share a key - a weight cause, or the same endpoints and
// type - share one uniform U and are present when U < p (the comonotonic coupling); keys
// are independent of one another.
func exactRisk(snap graph.Snapshot, prob []float64) (anyP float64, perJewel map[string]float64) {
	nodes := snap.NodeByID()
	groups := map[uint64][]int{}
	var keys []uint64
	for i, e := range snap.Edges {
		k := edgeKey(e)
		if name, _ := e.Properties[ontology.PropWeightCause].(string); name != "" {
			k = causeKey(name)
		}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], i)
	}
	// Each key's worlds: U falls between two consecutive distinct thresholds, and the edges
	// whose probability is at least the upper one are present.
	type world struct {
		weight  float64
		present []int
	}
	options := make([][]world, len(keys))
	for gi, k := range keys {
		idx := groups[k]
		ts := []float64{0, 1}
		for _, i := range idx {
			ts = append(ts, prob[i])
		}
		sort.Float64s(ts)
		for j := 0; j+1 < len(ts); j++ {
			a, b := ts[j], ts[j+1]
			if b <= a {
				continue
			}
			w := world{weight: b - a}
			for _, i := range idx {
				if prob[i] >= b {
					w.present = append(w.present, i)
				}
			}
			options[gi] = append(options[gi], w)
		}
	}

	var seeds, jewels []string
	listed := map[string]bool{}
	for _, n := range snap.Nodes {
		if listed[n.ID] {
			continue
		}
		listed[n.ID] = true
		n = nodes[n.ID]
		if n.IsSeed() {
			seeds = append(seeds, n.ID)
		}
		if n.Bool(ontology.PropCrownJewel) {
			jewels = append(jewels, n.ID)
		}
	}
	perJewel = map[string]float64{}
	present := make([]bool, len(snap.Edges))
	choice := make([]int, len(keys))
	for {
		weight := 1.0
		clear(present)
		for gi, c := range choice {
			weight *= options[gi][c].weight
			for _, i := range options[gi][c].present {
				present[i] = true
			}
		}
		visited := map[string]bool{}
		stack := append([]string(nil), seeds...)
		for _, s := range seeds {
			visited[s] = true
		}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for i, e := range snap.Edges {
				if present[i] && e.From == cur && !visited[e.To] {
					visited[e.To] = true
					stack = append(stack, e.To)
				}
			}
		}
		anyHit := false
		for _, j := range jewels {
			hit := visited[j]
			if n := nodes[j]; n.IsSeed() && !n.HeldByAttacker() {
				// Reachable, not held: only an edge from a reached node compromises it.
				hit = false
				for i, e := range snap.Edges {
					if present[i] && e.To == j && e.From != j && visited[e.From] {
						hit = true
					}
				}
			}
			if hit {
				perJewel[j] += weight
				anyHit = true
			}
		}
		if anyHit {
			anyP += weight
		}
		// Next combination.
		gi := 0
		for ; gi < len(choice); gi++ {
			choice[gi]++
			if choice[gi] < len(options[gi]) {
				break
			}
			choice[gi] = 0
		}
		if gi == len(choice) {
			break
		}
	}
	return anyP, perJewel
}

func within(t *testing.T, what string, got, want float64, n int) {
	t.Helper()
	se := math.Sqrt(want*(1-want)/float64(n)) + 1e-9
	if math.Abs(got-want) > 5*se+1e-12 {
		t.Errorf("%s: simulated %.4f, exact %.4f (%.1f standard errors off)", what, got, want, math.Abs(got-want)/se)
	}
}

func TestSimulateRiskAgreesWithExactEnumeration(t *testing.T) {
	SetAttackerProfilePriors("")
	ctx := context.Background()
	r := rand.New(rand.NewSource(20260925))
	const trials = 40000
	for g := 0; g < 30; g++ {
		snap := randomSnapshot(r, 3+r.Intn(5), 3+r.Intn(8))
		sim, err := SimulateRisk(ctx, snap, trials, uint64(g)+1)
		if err != nil {
			t.Fatal(err)
		}
		prob := make([]float64, len(snap.Edges))
		for i, e := range snap.Edges {
			prob[i] = clampProb(e.ExploitProbability)
		}
		anyP, perJewel := exactRisk(snap, prob)
		within(t, fmt.Sprintf("graph %d any", g), sim.AnyCompromiseProbability, anyP, trials)
		for _, j := range sim.CrownJewels {
			within(t, fmt.Sprintf("graph %d jewel %s", g, j.ID), j.CompromiseProbability, perJewel[j.ID], trials)
		}
		// Each attacker profile is the same reachability at its conditioned probabilities.
		nodes := snap.NodeByID()
		profs := currentProfiles()
		probs := make([]float64, len(profs))
		for ci, pc := range sim.ProfileCompromise {
			cond := make([]float64, len(snap.Edges))
			for i, e := range snap.Edges {
				basis, _, _ := weightBasisOf(e, nodes[e.From], nodes[e.To])
				profileProbs(prob[i], basis, profs, probs)
				cond[i] = probs[ci]
			}
			want, _ := exactRisk(snap, cond)
			within(t, fmt.Sprintf("graph %d profile %s", g, pc.Profile), pc.Probability, want, trials)
		}
	}
}

// Common random numbers, the property a what-if and a fix's verification rest on: the
// graph after a cut runs the same trials as the graph before it, so no trial reaches more
// afterwards, and a cut on an edge no route to a jewel crosses changes nothing at all.
func TestACutNeverRaisesRiskAndAnIrrelevantCutChangesNothing(t *testing.T) {
	ctx := context.Background()
	r := rand.New(rand.NewSource(7))
	point := RiskOptions{PointOnly: true}
	for g := 0; g < 12; g++ {
		snap := randomSnapshot(r, 10+r.Intn(20), 20+r.Intn(40))
		before, err := SimulateRiskWith(ctx, snap, 600, 3, point)
		if err != nil {
			t.Fatal(err)
		}
		relevant := relevantEdges(snap)
		for i, e := range snap.Edges {
			res, err := WhatIfFromWith(ctx, snap, before, []EdgeCut{{From: e.From, To: e.To, Type: e.Type}}, 600, 3, point)
			if err != nil {
				t.Fatal(err)
			}
			if res.RiskReduction() < 0 || res.ExpectedReduction() < 0 {
				t.Fatalf("graph %d, cutting edge %d raised the risk: any %+.4f, expected %+.4f", g, i, -res.RiskReduction(), -res.ExpectedReduction())
			}
			after := map[string]float64{}
			for _, j := range res.AfterRisk.CrownJewels {
				after[j.ID] = j.CompromiseProbability
			}
			for _, j := range before.CrownJewels {
				if after[j.ID] > j.CompromiseProbability {
					t.Fatalf("graph %d, cutting edge %d raised jewel %s from %.4f to %.4f", g, i, j.ID, j.CompromiseProbability, after[j.ID])
				}
			}
			if !relevant[i] && !reflect.DeepEqual(res.AfterRisk, before) {
				t.Fatalf("graph %d, cutting edge %d (%s→%s), which no route to a jewel crosses, changed the risk:\n before %+v\n after  %+v",
					g, i, e.From, e.To, before, res.AfterRisk)
			}
		}
	}
}

// relevantEdges marks the edges some route from a seed to a jewel could cross: the source
// is reachable from a seed, and the target is a jewel or reaches one.
func relevantEdges(snap graph.Snapshot) []bool {
	nodes := snap.NodeByID()
	out := map[string][]string{}
	in := map[string][]string{}
	for _, e := range snap.Edges {
		out[e.From] = append(out[e.From], e.To)
		in[e.To] = append(in[e.To], e.From)
	}
	walk := func(start []string, next map[string][]string) map[string]bool {
		seen := map[string]bool{}
		stack := append([]string(nil), start...)
		for _, s := range start {
			seen[s] = true
		}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, n := range next[cur] {
				if !seen[n] {
					seen[n] = true
					stack = append(stack, n)
				}
			}
		}
		return seen
	}
	var seeds, jewels []string
	for _, n := range snap.Nodes {
		n = nodes[n.ID]
		if n.IsSeed() {
			seeds = append(seeds, n.ID)
		}
		if n.Bool(ontology.PropCrownJewel) {
			jewels = append(jewels, n.ID)
		}
	}
	fromSeed, toJewel := walk(seeds, out), walk(jewels, in)
	rel := make([]bool, len(snap.Edges))
	for i, e := range snap.Edges {
		rel[i] = e.From != e.To && fromSeed[e.From] && toJewel[e.To]
	}
	return rel
}

// The draws are keyed by edge, not by position, so the order a store returns the edges
// in - which it does not promise to keep - changes nothing.
func TestEdgeOrderDoesNotChangeTheSimulation(t *testing.T) {
	ctx := context.Background()
	r := rand.New(rand.NewSource(11))
	for g := 0; g < 5; g++ {
		snap := randomSnapshot(r, 15, 40)
		want, err := SimulateRisk(ctx, snap, 400, 9)
		if err != nil {
			t.Fatal(err)
		}
		shuffled := graph.Snapshot{Nodes: snap.Nodes, Edges: append([]ontology.Edge(nil), snap.Edges...)}
		r.Shuffle(len(shuffled.Edges), func(i, j int) { shuffled.Edges[i], shuffled.Edges[j] = shuffled.Edges[j], shuffled.Edges[i] })
		got, err := SimulateRisk(ctx, shuffled, 400, 9)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("graph %d: reordering the edges changed the result:\n got  %+v\n want %+v", g, got, want)
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
	if paths := FindCriticalPaths(snap); len(paths) != 1 {
		t.Errorf("jewel listed twice: %d paths, want 1", len(paths))
	}
}
