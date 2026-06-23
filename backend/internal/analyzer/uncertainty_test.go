package analyzer

import (
	"math"
	"math/rand/v2"
	"testing"
)

func TestConcentrationMonotonic(t *testing.T) {
	// More basis confidence ⇒ more pseudo-observations ⇒ a tighter posterior.
	prev := concentration(0)
	for c := 0.1; c <= 1.0001; c += 0.1 {
		k := concentration(c)
		if k < prev {
			t.Errorf("concentration not monotonic: c=%.1f gave %.2f < %.2f", c, k, prev)
		}
		prev = k
	}
	if concentration(0.95) <= concentration(0.35) {
		t.Error("kev-grade confidence should concentrate more than a heuristic")
	}
}

func TestBetaParamsMeanIsPoint(t *testing.T) {
	for _, tc := range []struct{ p, c float64 }{{0.2, 0.4}, {0.5, 0.9}, {0.9, 0.35}} {
		a, b := betaParams(tc.p, tc.c)
		mean := a / (a + b)
		if math.Abs(mean-tc.p) > 1e-9 {
			t.Errorf("betaParams(%.2f,%.2f): mean %.4f != point %.2f", tc.p, tc.c, mean, tc.p)
		}
	}
}

func TestSampleBetaEmpiricalMean(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	a, b := betaParams(0.7, 0.9)
	const n = 40000
	sum := 0.0
	for i := 0; i < n; i++ {
		sum += sampleBeta(rng, a, b)
	}
	if mean := sum / n; math.Abs(mean-0.7) > 0.01 {
		t.Errorf("empirical Beta mean %.4f, want ≈ 0.70", mean)
	}
}

// twoHops builds a 2-hop path whose hops carry a given weight confidence, so the
// credible interval reflects exactly that evidence strength. Both hops p=0.5 ⇒
// Score = 0.25.
func twoHops(conf float64) []Step {
	return []Step{
		{From: "a", To: "b", Probability: 0.5, WeightConfidence: conf},
		{From: "b", To: "c", Probability: 0.5, WeightConfidence: conf},
	}
}

func TestScoreCredibleIntervalBracketsAndDeterministic(t *testing.T) {
	steps := twoHops(0.6)
	lo, hi := scoreCredibleInterval("ap-x", steps, 0.25)
	if !(lo <= 0.25 && 0.25 <= hi) {
		t.Errorf("point 0.25 not bracketed by [%.4f, %.4f]", lo, hi)
	}
	if hi <= lo {
		t.Errorf("degenerate interval [%.4f, %.4f]", lo, hi)
	}
	lo2, hi2 := scoreCredibleInterval("ap-x", steps, 0.25)
	if lo != lo2 || hi != hi2 {
		t.Errorf("same id must be deterministic: [%.6f,%.6f] vs [%.6f,%.6f]", lo, hi, lo2, hi2)
	}
}

func TestScoreCredibleIntervalTighterWithEvidence(t *testing.T) {
	loW, hiW := scoreCredibleInterval("p", twoHops(0.35), 0.25) // heuristic, loose
	loS, hiS := scoreCredibleInterval("p", twoHops(0.95), 0.25) // kev/runtime, tight
	wide := hiW - loW
	tight := hiS - loS
	if tight >= wide {
		t.Errorf("evidence-backed interval (%.4f) should be tighter than heuristic (%.4f)", tight, wide)
	}
}

func TestScoreCredibleIntervalEmptyPath(t *testing.T) {
	lo, hi := scoreCredibleInterval("p", nil, 0.42)
	if lo != 0.42 || hi != 0.42 {
		t.Errorf("empty path should collapse to the point, got [%.4f, %.4f]", lo, hi)
	}
}
