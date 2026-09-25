package analyzer

import (
	"math"
	"testing"
)

// stepsWith builds an n-hop path whose hops all carry probability p and weight
// basis b - so a test exercises exactly one (basis, skill) regime.
func stepsWith(n int, p float64, basis string) []Step {
	out := make([]Step, n)
	for i := range out {
		out[i] = Step{From: "x", To: "y", Probability: p, WeightBasis: basis}
	}
	return out
}

func profByName(ps []ProfileScore, name string) ProfileScore {
	for _, p := range ps {
		if p.Profile == name {
			return p
		}
	}
	return ProfileScore{}
}

func TestAttackerMixtureOrdersByCapability(t *testing.T) {
	t.Cleanup(func() { SetAttackerProfilePriors("") })
	SetAttackerProfilePriors("")

	mix, profs := attackerMixture(stepsWith(2, 0.5, "heuristic"))
	apt := profByName(profs, "apt").Score
	crim := profByName(profs, "criminal").Score
	commodity := profByName(profs, "commodity").Score
	if !(apt > crim && crim > commodity) {
		t.Errorf("capability ordering broken: apt=%.3f criminal=%.3f commodity=%.3f", apt, crim, commodity)
	}
	// The marginal must equal Σ prior·score.
	want := 0.0
	for _, p := range profs {
		want += p.Prior * p.Score
	}
	if math.Abs(mix-want) > 1e-9 {
		t.Errorf("mixture %.6f != Σ prior·score %.6f", mix, want)
	}
}

func TestAttackerMixtureKevIsSkillInvariant(t *testing.T) {
	t.Cleanup(func() { SetAttackerProfilePriors("") })
	SetAttackerProfilePriors("")

	// A KEV/public-exploit hop barely depends on skill; a heuristic hop depends on it
	// a lot. So the apt-vs-commodity gap must be much smaller for KEV than heuristic.
	_, kev := attackerMixture(stepsWith(2, 0.7, "kev"))
	_, heur := attackerMixture(stepsWith(2, 0.7, "heuristic"))
	kevGap := profByName(kev, "apt").Score - profByName(kev, "commodity").Score
	heurGap := profByName(heur, "apt").Score - profByName(heur, "commodity").Score
	if !(kevGap < heurGap) {
		t.Errorf("KEV gap (%.3f) should be smaller than heuristic gap (%.3f)", kevGap, heurGap)
	}
}

func TestSetAttackerProfilePriorsOverrideAndNormalize(t *testing.T) {
	t.Cleanup(func() { SetAttackerProfilePriors("") })

	// Un-normalized override is renormalized; an unknown name is ignored.
	SetAttackerProfilePriors("commodity:2,criminal:1,apt:1,martian:5")
	ps := currentProfiles()
	sum := 0.0
	for _, p := range ps {
		sum += p.Prior
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("priors must renormalize to 1, got %.4f", sum)
	}
	if got := profByNameP(ps, "commodity").Prior; math.Abs(got-0.5) > 1e-9 {
		t.Errorf("commodity prior = %.4f, want 0.5 (2 of 4)", got)
	}
	if len(ps) != 3 {
		t.Errorf("unknown profile must not be added: got %d profiles", len(ps))
	}
}

func TestSetAttackerProfilePriorsEmptyAndZeroKeepDefaults(t *testing.T) {
	t.Cleanup(func() { SetAttackerProfilePriors("") })

	SetAttackerProfilePriors("")
	if got := profByNameP(currentProfiles(), "commodity").Prior; math.Abs(got-0.5) > 1e-9 {
		t.Errorf("empty spec should keep default commodity prior 0.5, got %.4f", got)
	}
	// All-zero priors are nonsensical; fall back to defaults rather than divide by 0.
	SetAttackerProfilePriors("commodity:0,criminal:0,apt:0")
	if got := profByNameP(currentProfiles(), "apt").Prior; math.Abs(got-0.15) > 1e-9 {
		t.Errorf("all-zero spec should keep default apt prior 0.15, got %.4f", got)
	}
}

// A path with no hops is a crown jewel the attacker already holds (a direct-access
// path): certain against every profile, like its Score of 1. It used to read 0 here, so
// the "blended" figure beside a 100% path would have said nobody could walk it.
func TestAttackerMixtureEmptyPathIsCertain(t *testing.T) {
	mix, profs := attackerMixture(nil)
	if math.Abs(mix-1) > 1e-12 || len(profs) != len(currentProfiles()) {
		t.Fatalf("empty path: mixture %.3f, %d profiles; want 1 against each of %d", mix, len(profs), len(currentProfiles()))
	}
	for _, p := range profs {
		if p.Score != 1 {
			t.Errorf("profile %s scores %.3f on an empty path, want 1", p.Profile, p.Score)
		}
	}
}

func profByNameP(ps []AttackerProfile, name string) AttackerProfile {
	for _, p := range ps {
		if p.Name == name {
			return p
		}
	}
	return AttackerProfile{}
}

// The profiles average back to the edge's own probability, whatever the probability,
// the basis or the priors - including the operator's own ATTACKER_PROFILE_PRIORS.
func TestProfilesAverageBackToTheEdgeProbability(t *testing.T) {
	t.Cleanup(func() { SetAttackerProfilePriors("") })
	for _, spec := range []string{"", "commodity:0.1,criminal:0.2,apt:0.7", "apt:1", "commodity:1"} {
		SetAttackerProfilePriors(spec)
		profs := currentProfiles()
		probs := make([]float64, len(profs))
		for _, basis := range []string{"kev", "runtime", "epss", "cvss", "severity", "heuristic", ""} {
			for _, p := range []float64{0.01, 0.05, 0.2, 0.5, 0.8, 0.95, 0.999, 1} {
				profileProbs(p, basis, profs, probs)
				avg := 0.0
				for c, pr := range profs {
					avg += pr.Prior * probs[c]
				}
				want := math.Min(math.Max(p, probClamp), 1-probClamp) // p, kept off 0 and 1
				if math.Abs(avg-want) > 1e-9 {
					t.Errorf("priors %q basis %q p=%v: profiles average %.12f, want %.12f", spec, basis, p, avg, want)
				}
			}
		}
	}
}

// Anchored, the mixture changes the correlation and nothing else: one hop reads exactly
// its probability, and a chain reads between the independent product and its weakest
// hop. Before, the default priors pulled a lone 0.9 hop to 0.78 and CloudGoat's two-hop
// SSRF route from 81% to 64%, under a lens that can only raise a chain.
func TestTheMixtureSitsBetweenTheProductAndTheWeakestHop(t *testing.T) {
	t.Cleanup(func() { SetAttackerProfilePriors("") })
	bases := []string{"kev", "runtime", "epss", "cvss", "severity", "heuristic"}
	for _, spec := range []string{"", "commodity:0.1,criminal:0.2,apt:0.7"} {
		SetAttackerProfilePriors(spec)
		for _, basis := range bases {
			for _, p := range []float64{0.1, 0.5, 0.9, 0.99} {
				if mix, _ := attackerMixture(stepsWith(1, p, basis)); math.Abs(mix-p) > 1e-9 {
					t.Errorf("priors %q: one %s hop at %v reads %.6f", spec, basis, p, mix)
				}
			}
		}
		// Mixed chains: every combination of two and three hops over a spread of values.
		ps := []float64{0.2, 0.6, 0.95}
		for _, b1 := range bases {
			for _, b2 := range bases {
				for _, p1 := range ps {
					for _, p2 := range ps {
						for _, p3 := range ps {
							steps := []Step{{Probability: p1, WeightBasis: b1}, {Probability: p2, WeightBasis: b2}, {Probability: p3, WeightBasis: b1}}
							mix, _ := attackerMixture(steps)
							product, weakest := p1*p2*p3, math.Min(p1, math.Min(p2, p3))
							if mix < product-1e-12 || mix > weakest+1e-12 {
								t.Errorf("priors %q, %s/%s hops %v %v %v: mixture %.6f outside [product %.6f, weakest %.6f]",
									spec, b1, b2, p1, p2, p3, mix, product, weakest)
							}
						}
					}
				}
			}
		}
	}
}
