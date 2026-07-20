package analyzer

// Attacker-profile mixture - killing the independence assumption at the root.
//
// The naive path score ∏p treats every hop as independent. Real attack steps are
// positively correlated through a latent variable: the *attacker's capability*. A
// hop that stops a script-kiddie is trivial for a nation-state, and whoever clears
// one hard step tends to clear the next. We model that with a small set of attacker
// profiles c (commodity / criminal / apt), each with a prior P(c) and a skill that
// shifts every hop's success log-odds - scaled by how much that hop actually depends
// on skill (a public KEV exploit barely; a heuristic topology guess a lot). Within a
// profile, conditional independence is reasonable, so the product is honest there:
//
//	p(e|c) = sigmoid( logit(p(e)) + skill(c)·sensitivity(basis(e)) )
//	S_c(P) = ∏ p(e|c)
//	S(P)   = Σ_c P(c)·S_c(P)         (the marginal, correlation-aware score)
//
// Marginalizing over c reintroduces the positive correlation the bare product drops
// (the hops co-vary through the shared c), and the per-profile breakdown - "72% vs an
// APT, 18% vs commodity" - tells a reader whether a path is trivial for an APT but
// stops a commodity actor. It is an interpretive lens, NOT the triage axis: the
// ordering a team works through comes from Priority (see priority.go), which blends
// the naive Score with corroboration and target sensitivity. The naive Score is left
// untouched as the independent baseline; this is an additional, sharper lens on top.

import (
	"math"
	"strconv"
	"strings"
	"sync/atomic"
)

// AttackerProfile is one latent attacker archetype: a prior weight in the threat
// model and a skill offset (in logit units) applied to every hop, scaled by the
// hop's skill sensitivity. Negative skill = below the baseline attacker, positive =
// above.
type AttackerProfile struct {
	Name  string  `json:"name"`
	Prior float64 `json:"prior"`
	Skill float64 `json:"skill"`
}

// ProfileScore is a path's success probability against one attacker profile -
// ∏ p(e|c) - alongside that profile's prior. The set is the actionable breakdown
// behind the marginal MixtureScore.
type ProfileScore struct {
	Profile string  `json:"profile"`
	Prior   float64 `json:"prior"`
	Score   float64 `json:"score"`
}

// defaultAttackerProfiles encodes a conventional threat model: most attempts are
// commodity/opportunistic, a sizable minority organized e-crime, a small slice
// advanced. Skills are symmetric in logit space around the baseline criminal.
// Operators retune the priors (not the skills) via ATTACKER_PROFILE_PRIORS.
var defaultAttackerProfiles = []AttackerProfile{
	{Name: "commodity", Prior: 0.50, Skill: -1.6},
	{Name: "criminal", Prior: 0.35, Skill: 0.0},
	{Name: "apt", Prior: 0.15, Skill: 1.6},
}

// attackerProfiles holds the active set, swapped atomically at startup so the
// per-path scoring reads it lock-free (like pathWorkers).
var attackerProfiles atomic.Pointer[[]AttackerProfile]

// currentProfiles returns the configured profiles, or the defaults if unset.
func currentProfiles() []AttackerProfile {
	if p := attackerProfiles.Load(); p != nil {
		return *p
	}
	return defaultAttackerProfiles
}

// SetAttackerProfilePriors overrides the profile priors from a spec like
// "commodity:0.5,criminal:0.35,apt:0.15" (names match the defaults; unknown names
// and malformed entries are ignored). Priors are renormalized to sum to 1; an empty
// or all-zero spec keeps the defaults. The skills are model internals and stay
// fixed. Safe to call once at startup.
func SetAttackerProfilePriors(spec string) {
	base := append([]AttackerProfile(nil), defaultAttackerProfiles...)
	if spec = strings.TrimSpace(spec); spec != "" {
		overrides := map[string]float64{}
		for _, part := range strings.Split(spec, ",") {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) != 2 {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(kv[0]))
			f, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
			if err != nil || f < 0 {
				continue
			}
			overrides[name] = f
		}
		for i := range base {
			if v, ok := overrides[base[i].Name]; ok {
				base[i].Prior = v
			}
		}
	}
	sum := 0.0
	for _, p := range base {
		sum += p.Prior
	}
	if sum <= 0 {
		base = append([]AttackerProfile(nil), defaultAttackerProfiles...) // all-zero ⇒ keep defaults
	} else {
		for i := range base {
			base[i].Prior /= sum
		}
	}
	attackerProfiles.Store(&base)
}

// skillSensitivity is how much an edge's success depends on attacker capability,
// keyed by where its probability came from. A KEV with a public exploit or a live
// runtime alert is near skill-invariant (anyone can ride it); a bare severity label
// or an assumed topology default is exactly the step that separates a capable
// attacker from a commodity one.
func skillSensitivity(basis string) float64 {
	switch basis {
	case "kev":
		return 0.15
	case "runtime":
		return 0.25
	case "epss":
		return 0.45
	case "cvss":
		return 0.70
	case "severity":
		return 0.90
	default: // heuristic / unknown
		return 1.0
	}
}

func logit(p float64) float64 {
	if p < 1e-6 {
		p = 1e-6
	}
	if p > 1-1e-6 {
		p = 1 - 1e-6
	}
	return math.Log(p / (1 - p))
}

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }

// conditionalProb is p(e|c): the edge's success probability for an attacker whose
// skill shifts the base probability's log-odds by how much the hop depends on skill.
// The single source of truth shared by the per-path mixture score and the per-profile
// Monte Carlo, so the two stay consistent. At skill 0 it is exactly p (σ and logit are
// inverses), so the baseline "criminal" reproduces the raw model.
func conditionalProb(p float64, basis string, skill float64) float64 {
	return sigmoid(logit(p) + skill*skillSensitivity(basis))
}

// attackerMixture computes the marginal mixture score Σ P(c)·∏ p(e|c) for a path
// and the per-profile breakdown. Deterministic (closed form), so it never disturbs
// the byte-identical parallel-pathfinding guarantee. An empty path yields (0, nil).
func attackerMixture(steps []Step) (mixture float64, perProfile []ProfileScore) {
	if len(steps) == 0 {
		return 0, nil
	}
	profs := currentProfiles()
	perProfile = make([]ProfileScore, 0, len(profs))
	for _, c := range profs {
		s := 1.0
		for _, st := range steps {
			s *= conditionalProb(st.Probability, st.WeightBasis, c.Skill)
		}
		perProfile = append(perProfile, ProfileScore{Profile: c.Name, Prior: c.Prior, Score: s})
		mixture += c.Prior * s
	}
	return mixture, perProfile
}
