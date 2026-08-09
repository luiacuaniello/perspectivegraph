package analyzer

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

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

// sharedCauseSnap: two internet routes reach the jewel, both gated by the same
// weakness. With cause set, the two final hops are one shared draw (comonotonic), so
// they fail together; with cause empty they are independent.
func sharedCauseSnap(cause string) graph.Snapshot {
	return graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb", Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "a", Label: ontology.LabelContainer, Name: "a"},
			{ID: "b", Label: ontology.LabelContainer, Name: "b"},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "admin", Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeExposes, From: "lb", To: "a", ExploitProbability: 1.0},
			{Type: ontology.EdgeExposes, From: "lb", To: "b", ExploitProbability: 1.0},
			{Type: ontology.EdgeExploits, From: "a", To: "role", ExploitProbability: 0.5, Properties: map[string]any{ontology.PropWeightCause: cause}},
			{Type: ontology.EdgeExploits, From: "b", To: "role", ExploitProbability: 0.5, Properties: map[string]any{ontology.PropWeightCause: cause}},
		},
	}
}

// P3: two routes that rest on the SAME weakness are not real redundancy. Independent
// sampling reports P(jewel) = 1-(1-0.5)² = 0.75; the common-cause coupling reports the
// honest 0.5 (one weakness: it holds or it doesn't, and both routes go with it).
func TestSharedCauseCouplesReachability(t *testing.T) {
	indep := mustSimulate(t, sharedCauseSnap(""), 20000, 1).AnyCompromiseProbability
	if math.Abs(indep-0.75) > 0.02 {
		t.Errorf("independent routes: P(jewel) = %.4f, want ≈ 0.75", indep)
	}
	coupled := mustSimulate(t, sharedCauseSnap("CVE-X"), 20000, 1).AnyCompromiseProbability
	if math.Abs(coupled-0.5) > 0.02 {
		t.Errorf("common-cause routes: P(jewel) = %.4f, want ≈ 0.50 (they fail together)", coupled)
	}
	if coupled >= indep {
		t.Errorf("common-cause coupling (%.4f) should reduce compromise vs independent (%.4f)", coupled, indep)
	}
}

func TestSimulateRiskUnionExceedsBestPath(t *testing.T) {
	sim := mustSimulate(t, twoRouteSnap(), 20000, 1)
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
	sim := mustSimulate(t, twoRouteSnap(), 20000, 1)
	// The credible band (per-edge Beta resampling) must bracket the nominal estimate
	// and be visibly wide, since these inputs are heuristic/severity-derived (low
	// basis confidence ⇒ loose posteriors ⇒ a wide band).
	if !(sim.SensitivityLow < sim.AnyCompromiseProbability && sim.AnyCompromiseProbability < sim.SensitivityHigh) {
		t.Errorf("nominal %.3f not bracketed by band [%.3f, %.3f]",
			sim.AnyCompromiseProbability, sim.SensitivityLow, sim.SensitivityHigh)
	}
	if sim.SensitivityHigh-sim.SensitivityLow < 0.2 {
		t.Errorf("expected a wide sensitivity band for heuristic inputs, got [%.3f, %.3f]",
			sim.SensitivityLow, sim.SensitivityHigh)
	}
}

func TestMixtureCompromiseByProfile(t *testing.T) {
	SetAttackerProfilePriors("") // built-in defaults (commodity/criminal/apt)
	sim := mustSimulate(t, twoRouteSnap(), 20000, 1)
	if len(sim.ProfileCompromise) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(sim.ProfileCompromise))
	}
	by := map[string]float64{}
	for _, pc := range sim.ProfileCompromise {
		by[pc.Profile] = pc.Probability
	}
	apt, crim, comm := by["apt"], by["criminal"], by["commodity"]
	if !(apt > crim && crim > comm) {
		t.Errorf("capability ordering broken: apt=%.3f criminal=%.3f commodity=%.3f", apt, crim, comm)
	}
	// The criminal (skill 0) has p(e|criminal)=p exactly, so its reachability reproduces
	// the independent headline - the mixture is anchored on the baseline.
	if math.Abs(crim-sim.AnyCompromiseProbability) > 0.03 {
		t.Errorf("criminal R=%.3f should ≈ AnyCompromiseProbability %.3f", crim, sim.AnyCompromiseProbability)
	}
	want := 0.0
	for _, pc := range sim.ProfileCompromise {
		want += pc.Prior * pc.Probability
	}
	if math.Abs(sim.MixtureCompromiseProbability-want) > 1e-9 {
		t.Errorf("mixture %.6f != Σ prior·R %.6f", sim.MixtureCompromiseProbability, want)
	}
}

func TestSimulateRiskReproducible(t *testing.T) {
	a := mustSimulate(t, twoRouteSnap(), 5000, 42)
	b := mustSimulate(t, twoRouteSnap(), 5000, 42)
	if a.AnyCompromiseProbability != b.AnyCompromiseProbability {
		t.Errorf("same seed must be reproducible: %v vs %v", a.AnyCompromiseProbability, b.AnyCompromiseProbability)
	}
}

func TestKShortestPathsEnumeratesBothRoutes(t *testing.T) {
	paths := mustKShortest(t, twoRouteSnap(), "lb", "role", 5)
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
	r := mustWhatIf(t, snap, cuts, 20000, 7)

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

// The analyzer's expensive entry points take a context and return an error so an
// abandoned request stops the work (see SimulateRisk). These helpers keep the tests
// reading as before while still exercising the real signature.
func mustSimulate(t *testing.T, snap graph.Snapshot, iterations int, seed uint64) RiskSimulation {
	t.Helper()
	sim, err := SimulateRisk(context.Background(), snap, iterations, seed)
	if err != nil {
		t.Fatalf("SimulateRisk: %v", err)
	}
	return sim
}

func mustKShortest(t *testing.T, snap graph.Snapshot, src, dst string, k int) []AttackPath {
	t.Helper()
	paths, err := KShortestPaths(context.Background(), snap, src, dst, k)
	if err != nil {
		t.Fatalf("KShortestPaths: %v", err)
	}
	return paths
}

func mustWhatIf(t *testing.T, snap graph.Snapshot, cuts []EdgeCut, iterations int, seed uint64) WhatIfResult {
	t.Helper()
	res, err := WhatIf(context.Background(), snap, cuts, iterations, seed)
	if err != nil {
		t.Fatalf("WhatIf: %v", err)
	}
	return res
}

// A simulation must stop when its request is abandoned. Before this, the work was
// uninterruptible: a query that had already blown the server's write timeout, or whose
// client had hung up, kept a core busy until the last trial. That is what made aliasing
// the field an amplifier rather than merely a slow query.
func TestSimulateRiskStopsWhenTheRequestIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client is already gone

	start := time.Now()
	_, err := SimulateRisk(ctx, twoRouteSnap(), 50_000_000, 1)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a cancelled simulation returned a result - a truncated Monte Carlo would be published as fact")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want context.Canceled", err)
	}
	// 50M trials would take minutes; cancellation must land in milliseconds.
	if elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v - the work is not actually interruptible", elapsed)
	}
}

// The deadline case, which is what the HTTP write timeout produces.
func TestSimulateRiskHonoursADeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := SimulateRisk(ctx, twoRouteSnap(), 50_000_000, 1)
	if err == nil {
		t.Fatal("a simulation outran its deadline and returned a result anyway")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("overran the deadline by %v", d)
	}
}

// WhatIf runs two simulations; both must be interruptible, not just the first.
func TestWhatIfStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WhatIf(ctx, twoRouteSnap(), nil, 50_000_000, 1); err == nil {
		t.Fatal("a cancelled what-if returned a result")
	}
}
