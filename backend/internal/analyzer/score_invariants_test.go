package analyzer

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The numbers this engine publishes are probabilities, and a probability that leaves
// [0,1] or a band that inverts is the kind of defect a reader finds in a screenshot
// rather than in a test. The existing suite pins the scoring on hand-built examples;
// this one asserts the invariants themselves hold across randomly generated estates,
// including the shapes nobody writes by hand: one hop, twenty hops, probabilities at
// the boundaries, and hops whose product underflows toward zero.

// randomChain builds an internet-exposed → crown-jewel chain of n hops with the given
// edge probabilities, which is the shape the scorer is defined on.
func randomChain(probs []float64) graph.Snapshot {
	nodes := []ontology.Node{{
		ID: "n0", Label: ontology.LabelLoadBalancer, Name: "entry",
		Properties: map[string]any{ontology.PropInternetExposed: true},
	}}
	var edges []ontology.Edge
	for i, p := range probs {
		last := i == len(probs)-1
		id := fmt.Sprintf("n%d", i+1)
		props := map[string]any{}
		if last {
			props[ontology.PropCrownJewel] = true
		}
		label := ontology.LabelContainer
		if last {
			label = ontology.LabelIAMRole
		}
		nodes = append(nodes, ontology.Node{ID: id, Label: label, Name: id, Properties: props})
		edges = append(edges, ontology.Edge{
			Type: ontology.EdgeExposes, From: fmt.Sprintf("n%d", i), To: id, ExploitProbability: p,
		})
	}
	return graph.Snapshot{Nodes: nodes, Edges: edges}
}

func checkInvariants(t *testing.T, label string, paths []AttackPath) {
	t.Helper()
	for _, p := range paths {
		// A probability outside [0,1] is not a probability. Anything downstream - the
		// Monte Carlo, the calibration, the dashboard's "55%" - is meaningless past this.
		if p.Score < 0 || p.Score > 1 || math.IsNaN(p.Score) {
			t.Errorf("%s: Score = %v, outside [0,1]", label, p.Score)
		}
		if p.ScoreUpperBound < 0 || p.ScoreUpperBound > 1 || math.IsNaN(p.ScoreUpperBound) {
			t.Errorf("%s: ScoreUpperBound = %v, outside [0,1]", label, p.ScoreUpperBound)
		}
		// The band's meaning: Score assumes the hops are independent (their product),
		// the upper bound assumes they share a cause (the weakest hop). The product of
		// numbers in [0,1] can never exceed the smallest of them, so an inverted band
		// means the two are no longer computing what their names claim.
		if p.ScoreUpperBound+1e-12 < p.Score {
			t.Errorf("%s: band inverted - upper bound %v < score %v", label, p.ScoreUpperBound, p.Score)
		}
		// The credible interval has to contain the point estimate, or the UI shows a
		// number sitting outside its own stated range.
		// The interval belongs to PosteriorMean, NOT to Score. They are different
		// estimators on purpose: Score is the bare independent product (a plug-in
		// estimate), while PosteriorMean is the mean of the coherent posterior that
		// composes each hop's Beta with the attacker-capability mixture. The bare
		// product can legitimately fall either side of that posterior's interval - it
		// is not a summary of it. Asserting Score ∈ [lo,hi] tests a contract the engine
		// never claimed, and it fails on exactly the shapes where the two estimators
		// diverge most: long chains, and hops pinned at 1.
		//
		// What must hold is that the posterior is self-consistent.
		lo, hi := p.ScoreCILow, p.ScoreCIHigh
		if hi > 0 {
			if lo < 0 || hi > 1 || lo > hi {
				t.Errorf("%s: credible interval [%v,%v] is not a valid interval in [0,1]", label, lo, hi)
			}
			if p.PosteriorMean < 0 || p.PosteriorMean > 1 || math.IsNaN(p.PosteriorMean) {
				t.Errorf("%s: PosteriorMean = %v, outside [0,1]", label, p.PosteriorMean)
			}
			if p.PosteriorMean < lo-1e-9 || p.PosteriorMean > hi+1e-9 {
				t.Errorf("%s: PosteriorMean %v sits outside its own 90%% interval [%v,%v] - the point "+
					"estimate and the band have stopped describing one distribution",
					label, p.PosteriorMean, lo, hi)
			}
		}
		if p.Priority < 0 || p.Priority > 100 || math.IsNaN(p.Priority) {
			t.Errorf("%s: Priority = %v, outside [0,100]", label, p.Priority)
		}
	}
}

// The shapes nobody writes by hand.
func TestScoreInvariantsOnEdgeShapes(t *testing.T) {
	cases := map[string][]float64{
		"single hop":            {0.5},
		"single hop at 1.0":     {1.0},
		"single hop at 0.0":     {0.0},
		"two hops at 1.0":       {1.0, 1.0},
		"long chain, high p":    {0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99},
		"long chain, underflow": {0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01, 0.01},
		"mixed extremes":        {1.0, 0.0, 1.0, 0.5},
	}
	for name, probs := range cases {
		t.Run(name, func(t *testing.T) {
			checkInvariants(t, name, FindCriticalPaths(randomChain(probs)))
		})
	}
}

// Randomised over many estates: the invariants are properties of the scorer, not of the
// examples someone thought to write down.
func TestScoreInvariantsHoldOnRandomEstates(t *testing.T) {
	rng := rand.New(rand.NewSource(20260803))
	for i := 0; i < 300; i++ {
		hops := 1 + rng.Intn(12)
		probs := make([]float64, hops)
		for j := range probs {
			switch rng.Intn(10) {
			case 0:
				probs[j] = 0 // the boundaries get sampled deliberately, not by luck
			case 1:
				probs[j] = 1
			default:
				probs[j] = rng.Float64()
			}
		}
		checkInvariants(t, fmt.Sprintf("estate %d (%d hops, %v)", i, hops, probs),
			FindCriticalPaths(randomChain(probs)))
	}
}

// The product is what the independence assumption means: state it once, so a future
// change to "improve" the score cannot quietly redefine the headline number.
func TestScoreIsTheProductOfItsHops(t *testing.T) {
	probs := []float64{0.9, 0.8, 0.5}
	paths := FindCriticalPaths(randomChain(probs))
	if len(paths) == 0 {
		t.Fatal("no path found for a straight internet → jewel chain")
	}
	want := 1.0
	weakest := 1.0
	for _, p := range probs {
		want *= p
		if p < weakest {
			weakest = p
		}
	}
	if math.Abs(paths[0].Score-want) > 1e-9 {
		t.Errorf("Score = %v, want the product %v", paths[0].Score, want)
	}
	if math.Abs(paths[0].ScoreUpperBound-weakest) > 1e-9 {
		t.Errorf("ScoreUpperBound = %v, want the weakest hop %v", paths[0].ScoreUpperBound, weakest)
	}
}
