package analyzer

// Per-edge Bayesian uncertainty.
//
// A point probability p(e) hides how much evidence stands behind it: "0.9 because
// it's a KEV with a live runtime alert" and "0.9 because a severity label mapped
// to it" are worlds apart in trust, yet the product score treats them identically.
// We model each edge as a Beta(α,β) posterior whose *mean* is the point estimate p
// and whose *concentration* κ=α+β grows with the weight basis's confidence - many
// pseudo-observations for observed exploitation (kev/runtime), few for a heuristic
// guess. Propagating those posteriors yields an honest credible interval on a
// path's score and on the headline risk, replacing the old flat ±30% sensitivity
// band with one the evidence actually justifies. The point estimates (Score,
// AnyCompromiseProbability) are unchanged - this only quantifies how much to trust
// them.
//
// The sampler is Marsaglia-Tsang gamma → beta, so it adds ZERO dependencies, in
// keeping with the rest of the engine.

import (
	"hash/fnv"
	"math"
	"math/rand/v2"
	"sort"
)

const (
	concMin   = 3.0  // weakest evidence (no/heuristic basis) → a wide Beta
	concMax   = 80.0 // strongest evidence (kev/runtime) → a tight Beta
	concGamma = 3.0  // convexity: low-confidence bases fall toward concMin quickly
	betaEps   = 1e-4
	// scoreSamples is how many posterior draws build a path's credible interval.
	// Paths are short, so this is cheap; 256 is plenty for a stable 5th/95th pctile.
	scoreSamples = 256
)

// concentration maps a weight-basis confidence in [0,1] to a Beta concentration κ
// (effective pseudo-observations). Convex (γ=3) so a heuristic hop (≈0.35) stays
// loose while kev/runtime (≈0.9+) concentrates tightly around its point estimate.
func concentration(basisConf float64) float64 {
	c := basisConf
	if c < 0 {
		c = 0
	}
	if c > 1 {
		c = 1
	}
	return concMin + (concMax-concMin)*math.Pow(c, concGamma)
}

// kappaPrior is the Beta pseudo-count added to a real evidence count, so a single
// corroborating observation still yields a proper (not overconfident) posterior.
const kappaPrior = 2.0

// betaParams turns a point probability p, its basis confidence, and (optionally) the
// number of independent observations behind it into the (α,β) of a Beta posterior
// with mean p. When evidenceCount > 0 the concentration is evidence-count-derived
// (κ = count + prior) - the proper Bayesian width; otherwise it falls back to the
// basis-confidence heuristic. p is nudged off {0,1} so α,β stay strictly positive.
func betaParams(p, basisConf float64, evidenceCount int) (alpha, beta float64) {
	if p < betaEps {
		p = betaEps
	}
	if p > 1-betaEps {
		p = 1 - betaEps
	}
	k := concentration(basisConf)
	if evidenceCount > 0 {
		k = float64(evidenceCount) + kappaPrior
	}
	return p * k, (1 - p) * k
}

// sampleGamma draws from Gamma(shape, scale=1) via Marsaglia-Tsang, boosting the
// shape<1 case. Dependency-free; uses the rng's normal and uniform deviates.
func sampleGamma(rng *rand.Rand, shape float64) float64 {
	if shape < 1 {
		g := sampleGamma(rng, shape+1)
		return g * math.Pow(rng.Float64(), 1/shape)
	}
	d := shape - 1.0/3.0
	c := 1.0 / math.Sqrt(9*d)
	for {
		x := rng.NormFloat64()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := rng.Float64()
		// Squeeze test first, then the exact acceptance bound.
		if u < 1-0.0331*x*x*x*x {
			return d * v
		}
		if math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v
		}
	}
}

// sampleBeta draws from Beta(α,β) as X/(X+Y) with X~Gamma(α), Y~Gamma(β).
func sampleBeta(rng *rand.Rand, alpha, beta float64) float64 {
	x := sampleGamma(rng, alpha)
	y := sampleGamma(rng, beta)
	if x+y == 0 {
		return 0.5
	}
	return x / (x + y)
}

// unifiedScorePosterior samples the ONE coherent posterior of a path's success
// probability, composing the two uncertainties that the separate lenses used to keep
// apart: epistemic (each hop's probability is a Beta posterior whose width reflects
// its evidence) and attacker capability (the Σ_c P(c)·∏ p(e|c) mixture that
// reintroduces the positive correlation the bare product drops). Per draw it samples
// every hop's Beta once - the SAME uncertain world faces each attacker profile - and
// forms the attacker-marginal mixture at those sampled probabilities. The mean is the
// coherent point estimate (it even corrects the Jensen gap the plug-in mixture
// ignores); the 5th/95th percentiles are the credible interval that now brackets the
// mixture, not the independent product. Deterministic (seeded from the path id) so a
// parallel pass is byte-identical; an empty path collapses to (point, point, point).
func unifiedScorePosterior(id string, steps []Step, profiles []AttackerProfile, point float64) (mean, lo, hi float64) {
	if len(steps) == 0 {
		return point, point, point
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	rng := rand.New(rand.NewPCG(h.Sum64(), 0x243f6a8885a308d3)) // #nosec G404 -- deterministic PRNG for reproducible Beta sampling, not security-sensitive

	ab := make([][2]float64, len(steps))
	for i, st := range steps {
		a, b := betaParams(st.Probability, st.WeightConfidence, st.EvidenceCount)
		ab[i] = [2]float64{a, b}
	}
	sampled := make([]float64, len(steps))
	draws := make([]float64, scoreSamples)
	var sum float64
	for d := range draws {
		for i := range steps {
			sampled[i] = sampleBeta(rng, ab[i][0], ab[i][1]) // epistemic draw, shared across profiles
		}
		var mix float64
		for _, c := range profiles {
			prod := 1.0
			for i, st := range steps {
				prod *= conditionalProb(sampled[i], st.WeightBasis, c.Skill)
			}
			mix += c.Prior * prod
		}
		draws[d] = mix
		sum += mix
	}
	mean = sum / float64(len(draws))
	sort.Float64s(draws)
	lo = draws[pctIndex(0.05, scoreSamples)]
	hi = draws[pctIndex(0.95, scoreSamples)]
	// Keep the posterior mean inside its own interval despite MC noise / skew.
	if lo > mean {
		lo = mean
	}
	if hi < mean {
		hi = mean
	}
	return mean, lo, hi
}

// pctIndex is the nearest-rank index into a sorted slice of length n for quantile
// q in [0,1].
func pctIndex(q float64, n int) int {
	i := int(q*float64(n-1) + 0.5)
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}
