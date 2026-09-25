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
//	p(e|c) = sigmoid( logit(p(e)) + δ(e) + skill(c)·sensitivity(basis(e)) )
//	S_c(P) = ∏ p(e|c)
//	S(P)   = Σ_c P(c)·S_c(P)         (the marginal, correlation-aware score)
//
// δ(e) anchors the profiles to the edge's own probability: it is the one shift for
// which Σ_c P(c)·p(e|c) = p(e). The probabilities the collectors assign - EPSS, a KEV
// floor, a severity mapping - describe the attackers out there taken together, not one
// median attacker, so averaged over the profiles an edge must come back to exactly
// that. Without δ the model read p(e) as the "criminal" profile's probability, and the
// weak-attacker-heavy priors dragged every hop down: a single hop at 0.9, with no other
// hop to correlate with, came out at 0.78, and CloudGoat's two-hop SSRF route fell
// from 81% to 64% under a lens described as adding correlation - which can only raise
// a chain. Anchored, the mixture changes nothing but the correlation: one hop reads
// exactly p, and a path reads between the independent product and its weakest hop,
// Score ≤ S(P) ≤ ScoreUpperBound, because hops that rise and fall together with the
// attacker are positively associated and no joint law beats the Fréchet ceiling.
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

// probClamp keeps a probability off 0 and 1, where its log-odds - and so a shift in
// them - would be infinite.
const probClamp = 1e-6

// profileProbs fills out[c] with p(e|c) for every profile c: the edge's success
// probability for that attacker, anchored so the profiles average back to p (see the
// top of this file). The single source of truth shared by the per-path mixture score,
// the path posterior and the per-profile Monte Carlo, so the three stay consistent.
func profileProbs(p float64, basis string, profs []AttackerProfile, out []float64) {
	newAnchor(skillSensitivity(basis), profs).probs(p, 0, out)
}

// anchor solves for the shift δ that makes the profiles average back to an edge's
// probability, for one skill sensitivity k.
//
// It works in y = e^-δ rather than δ. With r = (1-p)/p = e^-logit(p) and w_c = e^-(s_c·k),
// profile c's probability σ(logit p + δ + s_c·k) is 1/(1 + r·y·w_c): rational in y, so
// the search needs no exponential at all - the w_c are computed once per k. The equation
//
//	f(x) = Σ_c P(c) / (1 + x·w_c) - p = 0,   x = r·y
//
// has f decreasing and convex in x, with its root between x = r·min(1/w_c), where every
// profile is at least p, and x = r·max(1/w_c), where every one is at most p. Newton's
// method from a good start converges in two or three steps; a step that would leave the
// bracket bisects instead.
type anchor struct {
	prior []float64 // P(c), normalised
	w     []float64 // e^-(s_c·k)
	yLo   float64   // the bracket on y: min and max of 1/w_c
	yHi   float64
}

func newAnchor(k float64, profs []AttackerProfile) anchor {
	a := anchor{prior: make([]float64, len(profs)), w: make([]float64, len(profs)), yLo: math.Inf(1), yHi: math.Inf(-1)}
	total := 0.0
	for _, c := range profs {
		total += c.Prior
	}
	for i, c := range profs {
		if total > 0 {
			a.prior[i] = c.Prior / total
		}
		a.w[i] = math.Exp(-c.Skill * k)
		inv := 1 / a.w[i]
		a.yLo, a.yHi = math.Min(a.yLo, inv), math.Max(a.yHi, inv)
	}
	return a
}

// probs fills out[c] with the anchored probabilities for an edge of probability p, and
// returns the solution's y. y0 is where the search starts - the y of a nearby
// probability, which is how the path posterior pays two iterations per draw rather than
// five; 0 starts from the middle of the bracket.
func (a anchor) probs(p, y0 float64, out []float64) float64 {
	if len(a.w) == 0 {
		return 1
	}
	// An edge at 0 or 1 is kept just inside, so it still has a root.
	p = math.Min(math.Max(p, probClamp), 1-probClamp)
	r := (1 - p) / p
	lo, hi := r*a.yLo, r*a.yHi
	x := r * y0
	if !(x > lo && x < hi) {
		x = math.Sqrt(lo * hi) // the geometric middle: y's bracket spans orders of magnitude
	}
	if hi-lo <= 1e-15*hi {
		x = lo // one skill for everyone: nothing to solve
	}
	for i := 0; ; i++ {
		f, df := -p, 0.0
		for c, w := range a.w {
			q := 1 / (1 + x*w)
			out[c] = q
			f += a.prior[c] * q
			df -= a.prior[c] * w * q * q
		}
		if math.Abs(f) < 1e-13 || hi-lo <= 1e-15*hi || i == 60 {
			return x / r
		}
		if f > 0 {
			lo = x // f decreases in x: the root is to the right
		} else {
			hi = x
		}
		next := x - f/df
		if df >= 0 || !(next > lo && next < hi) {
			next = (lo + hi) / 2
		}
		if next == x {
			return x / r
		}
		x = next
	}
}

// attackerMixture computes the marginal mixture score Σ P(c)·∏ p(e|c) for a path
// and the per-profile breakdown. Deterministic (closed form), so it never disturbs
// the byte-identical parallel-pathfinding guarantee. A path with no hops - a crown
// jewel the attacker already holds - is certain against every profile: the empty
// product is 1.
func attackerMixture(steps []Step) (mixture float64, perProfile []ProfileScore) {
	profs := currentProfiles()
	hop := make([][]float64, len(profs)) // hop[c][i]: hop i's probability against profile c
	for c := range hop {
		hop[c] = make([]float64, len(steps))
	}
	probs := make([]float64, len(profs))
	for i, st := range steps {
		profileProbs(st.Probability, st.WeightBasis, profs, probs)
		for c := range hop {
			hop[c][i] = probs[c]
		}
	}
	perProfile = make([]ProfileScore, 0, len(profs))
	for c, pr := range profs {
		score := chainProbability(steps, hop[c])
		perProfile = append(perProfile, ProfileScore{Profile: pr.Name, Prior: pr.Prior, Score: score})
		mixture += pr.Prior * score
	}
	return mixture, perProfile
}
