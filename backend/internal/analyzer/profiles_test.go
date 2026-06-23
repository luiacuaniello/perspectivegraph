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

func TestAttackerMixtureEmptyPath(t *testing.T) {
	mix, profs := attackerMixture(nil)
	if mix != 0 || profs != nil {
		t.Errorf("empty path should yield (0, nil), got (%.3f, %v)", mix, profs)
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
