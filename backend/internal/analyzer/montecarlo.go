package analyzer

// Monte Carlo risk quantification.
//
// The per-path score S(P)=∏p answers "how exploitable is *this* route". It can't
// answer the question a CISO actually asks: "what is the probability this crown
// jewel gets compromised at all", given that *many* routes reach it and they
// share edges. Multiplying or summing per-path scores double-counts the shared
// edges and ignores path multiplicity.
//
// So we simulate. Each trial realizes every edge independently (present with
// probability p), then asks: is the crown jewel reachable from any internet seed
// in this realized graph? The fraction of trials where it is reachable is an
// unbiased estimate of its compromise probability, correlations and all.
//
// Two honesty layers on the number:
//   - a Wilson 95% confidence interval quantifies *sampling* error (how many
//     trials we ran);
//   - a *credible band* quantifies *input* uncertainty. Rather than a flat ±30%
//     scaling, it draws each edge probability from its Beta posterior (a tight
//     posterior for kev/runtime-backed edges, a wide one for heuristic guesses -
//     see uncertainty.go) and re-runs reachability, an outer epistemic loop around
//     the inner aleatoric trials. The 5th-95th percentile spread of the result is
//     the band the *evidence* justifies: tight ⇒ trust the headline, wide ⇒ treat
//     it qualitatively. (Field names SensitivityLow/High are kept for the API.)

import (
	"math"
	"math/rand/v2"
	"sort"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// DefaultRiskIterations balances tightness of the confidence interval against
// cost; at 2000 trials a probability's 95% CI half-width is ≤ ~0.022.
const DefaultRiskIterations = 2000

// Credible band: the outer epistemic loop draws each edge probability from its
// Beta posterior `bandOuter` times, re-running reachability with `bandInner`
// trials each, and reports the 5th-95th percentile spread of the resulting
// any-compromise rate. Counts are modest (it runs once per pass) but enough for a
// stable band; the inner count is lower than the headline's since the band only
// needs a coarse spread, not a tight point estimate.
const (
	bandOuter = 64
	bandInner = 400
)

// CrownJewelRisk is one target's estimated compromise probability with a 95%
// Wilson confidence interval.
type CrownJewelRisk struct {
	ID                    string  `json:"id"`
	Name                  string  `json:"name"`
	Label                 string  `json:"label"`
	CompromiseProbability float64 `json:"compromise_probability"`
	CILow                 float64 `json:"ci_low"`
	CIHigh                float64 `json:"ci_high"`
}

// RiskSimulation is the result of a Monte Carlo run over the whole graph.
type RiskSimulation struct {
	Iterations int `json:"iterations"`
	// AnyCompromiseProbability is P(at least one crown jewel is reached).
	AnyCompromiseProbability float64 `json:"any_compromise_probability"`
	AnyCILow                 float64 `json:"any_ci_low"` // sampling-error CI (Wilson 95%)
	AnyCIHigh                float64 `json:"any_ci_high"`
	// Sensitivity band: AnyCompromiseProbability when every edge probability is
	// scaled down/up by 30%. Reflects model/input uncertainty, not sampling.
	SensitivityLow  float64 `json:"sensitivity_low"`
	SensitivityHigh float64 `json:"sensitivity_high"`
	// ExpectedCompromised is the mean number of crown jewels reached per trial.
	ExpectedCompromised float64          `json:"expected_compromised"`
	CrownJewels         []CrownJewelRisk `json:"crown_jewels"`
	// MixtureCompromiseProbability is P(any crown jewel reached) marginalized over the
	// attacker-profile mixture: Σ_c P(c)·R_c, where R_c conditions every edge on the
	// attacker's capability c (p(e|c)). AnyCompromiseProbability above samples edges
	// independently at the marginal p; this reintroduces the same latent-capability
	// correlation the *per-path* mixture score already reflects, so the headline risk
	// and the path scores are finally consistent (the naive number stays as the
	// independent baseline). ProfileCompromise is the per-profile breakdown.
	MixtureCompromiseProbability float64             `json:"mixture_compromise_probability,omitempty"`
	ProfileCompromise            []ProfileCompromise `json:"profile_compromise,omitempty"`
}

// ProfileCompromise is P(any crown jewel reached) against one attacker profile - the
// Monte Carlo counterpart of ProfileScore, so "80% vs an APT, 20% vs commodity" reads
// at the environment level, not just per path.
type ProfileCompromise struct {
	Profile     string  `json:"profile"`
	Prior       float64 `json:"prior"`
	Probability float64 `json:"probability"`
}

type probEdge struct {
	to    string
	p     float64
	conf  float64 // weight-basis confidence, drives the Beta posterior for the credible band
	basis string  // weight provenance (kev/epss/runtime/cvss/severity/heuristic), for p(e|c)
	evid  int     // independent observations behind p (0 = unknown ⇒ heuristic κ)
	cause string  // shared cause (CVE/credential id); edges sharing it are comonotonically coupled
}

// reachTrial runs one reachability trial from seeds over adj: a DFS that marks every
// node reachable through an edge present() admits. visited is cleared and reused.
func reachTrial(seeds []string, adj map[string][]probEdge, visited map[string]bool, present func(probEdge) bool) {
	clear(visited)
	stack := make([]string, 0, len(seeds))
	for _, s := range seeds {
		if !visited[s] {
			visited[s] = true
			stack = append(stack, s)
		}
	}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, e := range adj[cur] {
			if visited[e.to] {
				continue
			}
			if present(e) {
				visited[e.to] = true
				stack = append(stack, e.to)
			}
		}
	}
}

// comonotonicPresent returns a per-trial edge-presence test that couples edges sharing
// a weight cause: one uniform per cause (memoized in causeU, which the caller clears
// each trial), so a cause's failure knocks out ALL its edges together - the Fréchet
// coupling where P(all edges of a cause succeed) = min p rather than ∏p (P3). This is
// the common-cause correlation independent sampling misses: several paths that all rest
// on the same CVE are not independent redundancy. Causeless edges draw independently.
func comonotonicPresent(rng *rand.Rand, causeU map[string]float64) func(probEdge) bool {
	return func(e probEdge) bool {
		if e.cause == "" {
			return rng.Float64() <= e.p
		}
		u, ok := causeU[e.cause]
		if !ok {
			u = rng.Float64()
			causeU[e.cause] = u
		}
		return u <= e.p
	}
}

// SimulateRisk runs `iterations` Monte Carlo trials over the snapshot. seed makes
// a run reproducible, so the dashboard sees stable numbers between polls and a
// repeated what-if comparison doesn't jitter.
func SimulateRisk(snap graph.Snapshot, iterations int, seed uint64) RiskSimulation {
	if iterations <= 0 {
		iterations = DefaultRiskIterations
	}
	nodes := snap.NodeByID()

	adj := make(map[string][]probEdge, len(snap.Edges))
	for _, e := range snap.Edges {
		p := e.ExploitProbability
		if p <= 0 {
			p = 0.01
		}
		if p > 1 {
			p = 1
		}
		// Weight provenance (kev/runtime/epss/cvss/severity/heuristic): the confidence
		// sets how much the credible band lets this edge move; the basis drives p(e|c)
		// for the per-profile mixture - both shared with the per-path scoring.
		basis, conf, evid := weightBasisOf(e, nodes[e.From], nodes[e.To])
		cause, _ := e.Properties[ontology.PropWeightCause].(string)
		adj[e.From] = append(adj[e.From], probEdge{to: e.To, p: p, conf: conf, basis: basis, evid: evid, cause: cause})
	}

	var seeds, jewels []string
	for _, n := range snap.Nodes {
		if n.Bool(ontology.PropInternetExposed) {
			seeds = append(seeds, n.ID)
		}
		if n.Bool(ontology.PropCrownJewel) {
			jewels = append(jewels, n.ID)
		}
	}

	sim := RiskSimulation{Iterations: iterations}
	if len(seeds) == 0 || len(jewels) == 0 {
		return sim // nothing to reach, or nothing to reach from
	}

	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	hits := make(map[string]int, len(jewels))
	anyHits, totalCompromised := 0, 0
	visited := make(map[string]bool, len(nodes))
	// Reachability over the realized graph, with edges sharing a cause coupled
	// comonotonically (one draw per cause per trial) so common-cause weaknesses fail
	// together instead of as independent redundancy.
	causeU := make(map[string]float64)
	present := comonotonicPresent(rng, causeU)

	for it := 0; it < iterations; it++ {
		clear(causeU)
		reachTrial(seeds, adj, visited, present)

		compromised, anyThis := 0, false
		for _, j := range jewels {
			if visited[j] {
				hits[j]++
				compromised++
				anyThis = true
			}
		}
		if anyThis {
			anyHits++
		}
		totalCompromised += compromised
	}

	n := float64(iterations)
	sim.AnyCompromiseProbability = float64(anyHits) / n
	sim.AnyCILow, sim.AnyCIHigh = wilson(anyHits, iterations)
	sim.ExpectedCompromised = float64(totalCompromised) / n
	// Input-uncertainty credible band: resample each edge probability from its Beta
	// posterior and re-run reachability, so the UI can show how much the headline
	// rests on soft inputs - tight where the evidence is strong, wide where it's a
	// guess. Kept in the SensitivityLow/High fields to preserve the API.
	sim.SensitivityLow, sim.SensitivityHigh = anyCompromiseCredibleBand(seeds, jewels, adj, seed, sim.AnyCompromiseProbability)
	// Correlation-aware headline: marginalize the reachability over the attacker-profile
	// mixture, so it's consistent with the per-path mixture score (see the field docs).
	sim.MixtureCompromiseProbability, sim.ProfileCompromise = mixtureCompromise(seeds, jewels, adj, iterations, seed)
	for _, j := range jewels {
		node := nodes[j]
		lo, hi := wilson(hits[j], iterations)
		sim.CrownJewels = append(sim.CrownJewels, CrownJewelRisk{
			ID: j, Name: node.Name, Label: string(node.Label),
			CompromiseProbability: float64(hits[j]) / n, CILow: lo, CIHigh: hi,
		})
	}
	sort.Slice(sim.CrownJewels, func(i, j int) bool {
		if sim.CrownJewels[i].CompromiseProbability != sim.CrownJewels[j].CompromiseProbability {
			return sim.CrownJewels[i].CompromiseProbability > sim.CrownJewels[j].CompromiseProbability
		}
		return sim.CrownJewels[i].ID < sim.CrownJewels[j].ID
	})
	return sim
}

// anyCompromiseCredibleBand returns the 5th-95th percentile credible interval on
// P(at least one crown jewel reachable) under input uncertainty. The outer loop
// draws every edge probability from its Beta posterior (concentration set by the
// edge's basis confidence); the inner loop runs `bandInner` reachability trials at
// those drawn probabilities. The spread of the outer any-rates is the band the
// evidence justifies. Deterministic from `seed`. `nominal` is the point estimate,
// used only to guarantee the band brackets it (the reachability function is
// nonlinear, so the resampled mean can drift slightly off the point estimate).
func anyCompromiseCredibleBand(seeds, jewels []string, adj map[string][]probEdge, seed uint64, nominal float64) (lo, hi float64) {
	if len(seeds) == 0 || len(jewels) == 0 {
		return 0, 0
	}
	outerRng := rand.New(rand.NewPCG(seed, 0xa5a5a5a5a5a5a5a5))
	innerRng := rand.New(rand.NewPCG(seed^0x5bd1e995, 0x9e3779b97f4a7c15))
	visited := map[string]bool{}
	// Sampled copy of the adjacency, refilled each outer draw (same shape, so no
	// per-iteration allocation).
	sampled := make(map[string][]probEdge, len(adj))
	for k, es := range adj {
		sampled[k] = make([]probEdge, len(es))
	}

	causeU := make(map[string]float64)
	present := comonotonicPresent(innerRng, causeU)
	rates := make([]float64, bandOuter)
	for o := 0; o < bandOuter; o++ {
		for k, es := range adj {
			dst := sampled[k]
			for i, e := range es {
				a, b := betaParams(e.p, e.conf, e.evid)
				dst[i] = probEdge{to: e.to, p: sampleBeta(outerRng, a, b), cause: e.cause}
			}
		}
		anyHits := 0
		for it := 0; it < bandInner; it++ {
			clear(causeU)
			reachTrial(seeds, sampled, visited, present)
			for _, j := range jewels {
				if visited[j] {
					anyHits++
					break
				}
			}
		}
		rates[o] = float64(anyHits) / float64(bandInner)
	}
	sort.Float64s(rates)
	lo = rates[pctIndex(0.05, bandOuter)]
	hi = rates[pctIndex(0.95, bandOuter)]
	// Guarantee the band brackets the point estimate (only ever widening it).
	const eps = 1e-3
	if lo > nominal-eps {
		lo = nominal - eps
	}
	if hi < nominal+eps {
		hi = nominal + eps
	}
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

// mixtureCompromise marginalizes the any-compromise reachability over the attacker
// profiles: for each profile c it conditions every edge on capability c (p(e|c)) and
// estimates R_c = P(any crown jewel reachable | c), then returns Σ_c P(c)·R_c and the
// per-profile breakdown. Within a profile edges are still sampled independently, but
// conditioning on the shared c introduces the graph-wide positive correlation the
// independent headline drops - the same latent-capability mechanism as the per-path
// mixture, so the two are consistent. Deterministic from `seed`.
func mixtureCompromise(seeds, jewels []string, adj map[string][]probEdge, iterations int, seed uint64) (float64, []ProfileCompromise) {
	profs := currentProfiles()
	if iterations <= 0 || len(seeds) == 0 || len(jewels) == 0 || len(profs) == 0 {
		return 0, nil
	}
	// A reusable copy of the adjacency with per-profile conditioned probabilities.
	cond := make(map[string][]probEdge, len(adj))
	for k, es := range adj {
		cond[k] = make([]probEdge, len(es))
	}
	visited := make(map[string]bool)
	causeU := make(map[string]float64)
	out := make([]ProfileCompromise, 0, len(profs))
	mixture := 0.0
	for pi, c := range profs {
		for k, es := range adj {
			dst := cond[k]
			for i, e := range es {
				dst[i] = probEdge{to: e.to, p: conditionalProb(e.p, e.basis, c.Skill), cause: e.cause}
			}
		}
		rng := rand.New(rand.NewPCG(seed^(uint64(pi)+1)*0x9e3779b97f4a7c15, 0xdeadbeefcafef00d))
		present := comonotonicPresent(rng, causeU)
		anyHits := 0
		for it := 0; it < iterations; it++ {
			clear(causeU)
			reachTrial(seeds, cond, visited, present)
			for _, j := range jewels {
				if visited[j] {
					anyHits++
					break
				}
			}
		}
		rc := float64(anyHits) / float64(iterations)
		out = append(out, ProfileCompromise{Profile: c.Name, Prior: c.Prior, Probability: rc})
		mixture += c.Prior * rc
	}
	return mixture, out
}

// wilson returns the 95% Wilson score interval for a binomial proportion. It
// behaves near 0 and 1 (where the naive Wald interval would spill outside [0,1])
// - important here, since crown-jewel probabilities cluster at the extremes.
func wilson(successes, n int) (low, high float64) {
	if n == 0 {
		return 0, 0
	}
	const z = 1.959963984540054 // 97.5th percentile of the standard normal
	nn := float64(n)
	phat := float64(successes) / nn
	denom := 1 + z*z/nn
	center := (phat + z*z/(2*nn)) / denom
	margin := (z * math.Sqrt(phat*(1-phat)/nn+z*z/(4*nn*nn))) / denom
	low, high = center-margin, center+margin
	if low < 0 {
		low = 0
	}
	if high > 1 {
		high = 1
	}
	return low, high
}
