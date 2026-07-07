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
		a, b := betaParams(tc.p, tc.c, 0)
		mean := a / (a + b)
		if math.Abs(mean-tc.p) > 1e-9 {
			t.Errorf("betaParams(%.2f,%.2f): mean %.4f != point %.2f", tc.p, tc.c, mean, tc.p)
		}
	}
}

// An evidence count sets the Beta concentration directly (κ = count + prior),
// overriding the basis-confidence heuristic - the proper Bayesian width (P2 / #4).
func TestBetaParamsEvidenceCountSetsConcentration(t *testing.T) {
	a, b := betaParams(0.5, 0.35, 200) // heuristic-grade basis, but 200 observations
	if k := a + b; math.Abs(k-(200+kappaPrior)) > 1e-9 {
		t.Errorf("κ = %.2f, want count+prior %.2f", k, 200+kappaPrior)
	}
	if mean := a / (a + b); math.Abs(mean-0.5) > 1e-9 {
		t.Errorf("mean %.4f != point 0.5", mean)
	}
	ah, bh := betaParams(0.5, 0.35, 0) // same basis, no count ⇒ heuristic κ
	if (a + b) <= (ah + bh) {
		t.Error("200 observations should concentrate tighter than the heuristic κ")
	}
}

func TestSampleBetaEmpiricalMean(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	a, b := betaParams(0.7, 0.9, 0)
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

// The unified posterior composes epistemic (Beta) and attacker (mixture) uncertainty
// into one distribution whose credible interval brackets its own mean, deterministically.
func TestUnifiedPosteriorBracketsMeanAndDeterministic(t *testing.T) {
	steps := twoHops(0.6)
	mean, lo, hi := unifiedScorePosterior("ap-x", steps, currentProfiles(), 0.25)
	if !(lo <= mean && mean <= hi) {
		t.Errorf("posterior mean %.4f not bracketed by [%.4f, %.4f]", mean, lo, hi)
	}
	if hi <= lo {
		t.Errorf("degenerate interval [%.4f, %.4f]", lo, hi)
	}
	m2, lo2, hi2 := unifiedScorePosterior("ap-x", steps, currentProfiles(), 0.25)
	if mean != m2 || lo != lo2 || hi != hi2 {
		t.Errorf("same id must be deterministic: (%.6f,%.6f,%.6f) vs (%.6f,%.6f,%.6f)", mean, lo, hi, m2, lo2, hi2)
	}
}

func TestUnifiedPosteriorTighterWithEvidence(t *testing.T) {
	profs := currentProfiles()
	_, loW, hiW := unifiedScorePosterior("p", twoHops(0.35), profs, 0.25) // heuristic, loose
	_, loS, hiS := unifiedScorePosterior("p", twoHops(0.95), profs, 0.25) // kev/runtime, tight
	if wide, tight := hiW-loW, hiS-loS; tight >= wide {
		t.Errorf("evidence-backed interval (%.4f) should be tighter than heuristic (%.4f)", tight, wide)
	}
}

func TestUnifiedPosteriorEmptyPath(t *testing.T) {
	mean, lo, hi := unifiedScorePosterior("p", nil, currentProfiles(), 0.42)
	if mean != 0.42 || lo != 0.42 || hi != 0.42 {
		t.Errorf("empty path should collapse to the point, got mean=%.4f [%.4f, %.4f]", mean, lo, hi)
	}
}
