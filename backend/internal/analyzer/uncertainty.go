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

// betaParams turns a point probability p and its basis confidence into the (α,β)
// of a Beta posterior with mean p and evidence-scaled concentration. p is nudged
// off {0,1} so α,β stay strictly positive.
func betaParams(p, basisConf float64) (alpha, beta float64) {
	if p < betaEps {
		p = betaEps
	}
	if p > 1-betaEps {
		p = 1 - betaEps
	}
	k := concentration(basisConf)
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

// scoreCredibleInterval returns the 90% credible interval (5th–95th percentile)
// on a path's score S(P)=∏p, propagating each hop's Beta posterior. The point
// Score is the product of the posterior means; this brackets it with the spread
// the evidence justifies - tight when hops rest on observed exploitation, wide
// when they're heuristic guesses. Deterministic: the sampler is seeded from the
// path id, so a parallel pass produces a byte-identical interval. An empty path
// collapses to (score, score).
func scoreCredibleInterval(id string, steps []Step, score float64) (lo, hi float64) {
	if len(steps) == 0 {
		return score, score
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(id))
	rng := rand.New(rand.NewPCG(h.Sum64(), 0x243f6a8885a308d3))

	ab := make([][2]float64, len(steps))
	for i, st := range steps {
		a, b := betaParams(st.Probability, st.WeightConfidence)
		ab[i] = [2]float64{a, b}
	}
	samples := make([]float64, scoreSamples)
	for s := range samples {
		prod := 1.0
		for _, p := range ab {
			prod *= sampleBeta(rng, p[0], p[1])
		}
		samples[s] = prod
	}
	sort.Float64s(samples)
	lo = samples[pctIndex(0.05, scoreSamples)]
	hi = samples[pctIndex(0.95, scoreSamples)]
	// Keep the point estimate inside its own interval despite MC noise / Beta skew.
	if lo > score {
		lo = score
	}
	if hi < score {
		hi = score
	}
	return lo, hi
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
