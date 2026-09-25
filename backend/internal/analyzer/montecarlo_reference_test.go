package analyzer

// The Monte Carlo engine as it was before the reachability trials moved from string-keyed
// maps to integer indices. Kept verbatim as the reference the rewrite must reproduce bit
// for bit: montecarlo_equivalence_test.go runs both on the same graphs and seeds.

import (
	"context"
	"math/rand/v2"
	"sort"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type refProbEdge struct {
	to    string
	p     float64
	conf  float64 // weight-basis confidence, drives the Beta posterior for the credible band
	basis string  // weight provenance (kev/epss/runtime/cvss/severity/heuristic), for p(e|c)
	evid  int     // independent observations behind p (0 = unknown ⇒ heuristic κ)
	cause string  // shared cause (CVE/credential id); edges sharing it are comonotonically coupled
}

func refReachTrial(seeds []string, adj map[string][]refProbEdge, visited map[string]bool, present func(refProbEdge) bool) {
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

func refComonotonicPresent(rng *rand.Rand, causeU map[string]float64) func(refProbEdge) bool {
	return func(e refProbEdge) bool {
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

func refSimulateRisk(ctx context.Context, snap graph.Snapshot, iterations int, seed uint64) (RiskSimulation, error) {
	if iterations <= 0 {
		iterations = DefaultRiskIterations
	}
	nodes := snap.NodeByID()

	adj := make(map[string][]refProbEdge, len(snap.Edges))
	for _, e := range snap.Edges {
		p := clampProb(e.ExploitProbability)
		// Weight provenance (kev/runtime/epss/cvss/severity/heuristic): the confidence
		// sets how much the credible band lets this edge move; the basis drives p(e|c)
		// for the per-profile mixture - both shared with the per-path scoring.
		basis, conf, evid := weightBasisOf(e, nodes[e.From], nodes[e.To])
		cause, _ := e.Properties[ontology.PropWeightCause].(string)
		adj[e.From] = append(adj[e.From], refProbEdge{to: e.To, p: p, conf: conf, basis: basis, evid: evid, cause: cause})
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
		return sim, nil // nothing to reach, or nothing to reach from
	}

	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15)) // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
	hits := make(map[string]int, len(jewels))
	anyHits, totalCompromised := 0, 0
	visited := make(map[string]bool, len(nodes))
	// Reachability over the realized graph, with edges sharing a cause coupled
	// comonotonically (one draw per cause per trial) so common-cause weaknesses fail
	// together instead of as independent redundancy.
	causeU := make(map[string]float64)
	present := refComonotonicPresent(rng, causeU)

	for it := 0; it < iterations; it++ {
		// Checked on a stride rather than every trial: a context check is cheap but not
		// free, and a trial is cheaper still, so testing each one would show up in the
		// hot loop. 256 bounds the overshoot to well under a millisecond.
		if it&(cancelCheckStride-1) == 0 {
			if err := ctx.Err(); err != nil {
				return RiskSimulation{}, err
			}
		}
		clear(causeU)
		refReachTrial(seeds, adj, visited, present)

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
	var err error
	sim.SensitivityLow, sim.SensitivityHigh, err = refCredibleBand(ctx, seeds, jewels, adj, seed, sim.AnyCompromiseProbability)
	if err != nil {
		return RiskSimulation{}, err
	}
	// Correlation-aware headline: marginalize the reachability over the attacker-profile
	// mixture, so it's consistent with the per-path mixture score (see the field docs).
	sim.MixtureCompromiseProbability, sim.ProfileCompromise, err = refMixtureCompromise(ctx, seeds, jewels, adj, iterations, seed)
	if err != nil {
		return RiskSimulation{}, err
	}
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
	return sim, nil
}

func refCredibleBand(ctx context.Context, seeds, jewels []string, adj map[string][]refProbEdge, seed uint64, nominal float64) (lo, hi float64, err error) {
	if len(seeds) == 0 || len(jewels) == 0 {
		return 0, 0, nil
	}
	outerRng := rand.New(rand.NewPCG(seed, 0xa5a5a5a5a5a5a5a5))            // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
	innerRng := rand.New(rand.NewPCG(seed^0x5bd1e995, 0x9e3779b97f4a7c15)) // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
	visited := map[string]bool{}
	// Sampled copy of the adjacency, refilled each outer draw (same shape, so no
	// per-iteration allocation).
	sampled := make(map[string][]refProbEdge, len(adj))
	for k, es := range adj {
		sampled[k] = make([]refProbEdge, len(es))
	}
	// The draws below are handed to edges in the order the sources are visited, so that
	// order has to be fixed: ranging over the map itself gave every run its own order,
	// and the band came out different on every call with the same seed - measured, twenty
	// repeats out of twenty - although `seed` is documented as the way to reproduce it.
	sources := make([]string, 0, len(adj))
	for k := range adj {
		sources = append(sources, k)
	}
	sort.Strings(sources)

	causeU := make(map[string]float64)
	present := refComonotonicPresent(innerRng, causeU)
	rates := make([]float64, bandOuter)
	for o := 0; o < bandOuter; o++ {
		if e := ctx.Err(); e != nil {
			return 0, 0, e
		}
		for _, k := range sources {
			es, dst := adj[k], sampled[k]
			for i, e := range es {
				a, b := betaParams(e.p, e.conf, e.evid)
				dst[i] = refProbEdge{to: e.to, p: sampleBeta(outerRng, a, b), cause: e.cause}
			}
		}
		anyHits := 0
		for it := 0; it < bandInner; it++ {
			clear(causeU)
			refReachTrial(seeds, sampled, visited, present)
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
	return lo, hi, nil
}

func refMixtureCompromise(ctx context.Context, seeds, jewels []string, adj map[string][]refProbEdge, iterations int, seed uint64) (float64, []ProfileCompromise, error) {
	profs := currentProfiles()
	if iterations <= 0 || len(seeds) == 0 || len(jewels) == 0 || len(profs) == 0 {
		return 0, nil, nil
	}
	// A reusable copy of the adjacency with per-profile conditioned probabilities.
	cond := make(map[string][]refProbEdge, len(adj))
	for k, es := range adj {
		cond[k] = make([]refProbEdge, len(es))
	}
	visited := make(map[string]bool)
	causeU := make(map[string]float64)
	out := make([]ProfileCompromise, 0, len(profs))
	mixture := 0.0
	for pi, c := range profs {
		for k, es := range adj {
			dst := cond[k]
			for i, e := range es {
				dst[i] = refProbEdge{to: e.to, p: conditionalProb(e.p, e.basis, c.Skill), cause: e.cause}
			}
		}
		rng := rand.New(rand.NewPCG(seed^(uint64(pi)+1)*0x9e3779b97f4a7c15, 0xdeadbeefcafef00d)) // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
		present := refComonotonicPresent(rng, causeU)
		anyHits := 0
		for it := 0; it < iterations; it++ {
			clear(causeU)
			refReachTrial(seeds, cond, visited, present)
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
	return mixture, out, nil
}
