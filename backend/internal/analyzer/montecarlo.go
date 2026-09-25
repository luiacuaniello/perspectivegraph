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
	"context"
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

// mcGraph is a snapshot compiled for Monte Carlo trials: nodes and weight causes as
// dense indices, adjacency as lists of edge indices, and each edge's attributes in
// slices indexed by edge. A trial then touches slices and never hashes a string.
//
// The trials used to walk the snapshot as it came - adjacency in a map keyed by node id,
// a visited set in another map cleared before every trial, a map of per-cause draws - and
// on a 4,000-node graph one trial cost a third of a millisecond, most of it hashing. A
// simulation runs tens of thousands of them. The walk below is the same one, in the same
// order, drawing the same random numbers in the same sequence, so every result is
// identical bit for bit; montecarlo_equivalence_test.go holds it to the old code.
type mcGraph struct {
	nodes map[string]ontology.Node
	ids   []string
	index map[string]int32

	seeds  []int32
	jewels []int32 // in node order, each once

	adj   [][]int32 // per source node, its edges in snapshot order
	to    []int32
	cause []int32 // -1: no shared cause
	p     []float64
	conf  []float64
	basis []string
	evid  []int

	nCauses int
	// bandOrder is the order the credible band draws edge probabilities in: sources
	// sorted by id, each source's edges in snapshot order.
	bandOrder []int32
}

func compileGraph(snap graph.Snapshot) *mcGraph {
	g := &mcGraph{nodes: snap.NodeByID(), index: make(map[string]int32, len(snap.Nodes))}
	id := func(s string) int32 {
		if i, ok := g.index[s]; ok {
			return i
		}
		i := int32(len(g.ids)) // #nosec G115 -- node count is far below 2^31
		g.index[s] = i
		g.ids = append(g.ids, s)
		g.adj = append(g.adj, nil)
		return i
	}
	for _, n := range snap.Nodes {
		id(n.ID)
	}
	causes := map[string]int32{}
	for _, e := range snap.Edges {
		from, to := id(e.From), id(e.To)
		// Weight provenance (kev/runtime/epss/cvss/severity/heuristic): the confidence
		// sets how much the credible band lets this edge move; the basis drives p(e|c)
		// for the per-profile mixture - both shared with the per-path scoring.
		basis, conf, evid := weightBasisOf(e, g.nodes[e.From], g.nodes[e.To])
		c := int32(-1)
		if name, _ := e.Properties[ontology.PropWeightCause].(string); name != "" {
			ci, ok := causes[name]
			if !ok {
				ci = int32(len(causes)) // #nosec G115 -- cause count is far below 2^31
				causes[name] = ci
			}
			c = ci
		}
		eid := int32(len(g.to)) // #nosec G115 -- edge count is far below 2^31
		g.to = append(g.to, to)
		g.cause = append(g.cause, c)
		g.p = append(g.p, clampProb(e.ExploitProbability))
		g.conf = append(g.conf, conf)
		g.basis = append(g.basis, basis)
		g.evid = append(g.evid, evid)
		g.adj[from] = append(g.adj[from], eid)
	}
	g.nCauses = len(causes)
	// Each node is a seed or a jewel once, however many times the snapshot lists it. A
	// node listed twice - which a graph written by concurrent replicas before 1.19 can
	// hold - was counted twice as a jewel: a compromise probability of 2, and a Wilson
	// interval of NaN that the API could not encode.
	counted := make(map[int32]bool, len(snap.Nodes))
	for _, n := range snap.Nodes {
		i := g.index[n.ID]
		if counted[i] {
			continue
		}
		counted[i] = true
		if g.nodes[n.ID].Bool(ontology.PropInternetExposed) {
			g.seeds = append(g.seeds, i)
		}
		if g.nodes[n.ID].Bool(ontology.PropCrownJewel) {
			g.jewels = append(g.jewels, i)
		}
	}
	var sources []int32
	for i, es := range g.adj {
		if len(es) > 0 {
			sources = append(sources, int32(i)) // #nosec G115 -- node count is far below 2^31
		}
	}
	sort.Slice(sources, func(a, b int) bool { return g.ids[sources[a]] < g.ids[sources[b]] })
	for _, src := range sources {
		g.bandOrder = append(g.bandOrder, g.adj[src]...)
	}
	return g
}

// trials runs reachability trials over a compiled graph. visited and the per-cause draws
// are stamped with a generation instead of cleared, so starting a trial costs nothing.
type trials struct {
	g        *mcGraph
	rng      *rand.Rand
	gen      uint32
	visited  []uint32
	causeGen []uint32
	causeU   []float64
	stack    []int32
}

func newTrials(g *mcGraph, rng *rand.Rand) *trials {
	return &trials{g: g, rng: rng, visited: make([]uint32, len(g.ids)),
		causeGen: make([]uint32, g.nCauses), causeU: make([]float64, g.nCauses)}
}

// run is one trial: a DFS from the seeds that crosses an edge when present admits it at
// probability prob[edge]. Edges sharing a weight cause are coupled comonotonically - one
// uniform per cause per trial - so a cause's failure knocks out all its edges together:
// the Fréchet coupling where P(all edges of a cause succeed) = min p rather than ∏p. This
// is the common-cause correlation independent sampling misses: several paths that all
// rest on the same CVE are not independent redundancy. Causeless edges draw
// independently.
func (t *trials) run(prob []float64) {
	t.gen++
	if t.gen == 0 { // wrapped after 2^32 trials: the stamps are ambiguous, start over
		clear(t.visited)
		clear(t.causeGen)
		t.gen = 1
	}
	stack := t.stack[:0]
	for _, s := range t.g.seeds {
		if t.visited[s] != t.gen {
			t.visited[s] = t.gen
			stack = append(stack, s)
		}
	}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, e := range t.g.adj[cur] {
			to := t.g.to[e]
			if t.visited[to] == t.gen {
				continue
			}
			if t.present(e, prob[e]) {
				t.visited[to] = t.gen
				stack = append(stack, to)
			}
		}
	}
	t.stack = stack
}

func (t *trials) present(e int32, p float64) bool {
	c := t.g.cause[e]
	if c < 0 {
		return t.rng.Float64() <= p
	}
	if t.causeGen[c] != t.gen {
		t.causeU[c] = t.rng.Float64()
		t.causeGen[c] = t.gen
	}
	return t.causeU[c] <= p
}

func (t *trials) reached(node int32) bool { return t.visited[node] == t.gen }

// anyJewel reports whether the last trial reached any crown jewel.
func (t *trials) anyJewel() bool {
	for _, j := range t.g.jewels {
		if t.reached(j) {
			return true
		}
	}
	return false
}

// RiskOptions selects what a simulation computes beyond its point estimate. The zero
// value computes everything.
type RiskOptions struct {
	// PointOnly skips the credible band and the attacker-profile mixture. Those are most
	// of a simulation's cost - 25,600 band trials and three mixture runs, against 800
	// headline trials in a fix's verification - and the verification reads only the
	// point estimate.
	PointOnly bool
}

// SimulateRisk runs `iterations` Monte Carlo trials over the snapshot. seed makes
// a run reproducible, so the dashboard sees stable numbers between polls and a
// repeated what-if comparison doesn't jitter.
//
// It stops early when ctx is done, and then returns the error rather than a result.
// That distinction matters: a run cut short has fewer trials than it was asked for, so
// its probabilities are not the estimate anyone requested - they are a noisier one, and
// nothing on the wire would say so. A caller that got a truncated simulation back would
// publish it as fact. An abandoned request must therefore produce an error, not a number.
//
// Without this the work was uninterruptible: a request that had already exceeded the
// server's write timeout, or whose client had hung up, kept a core busy to completion.
// That is what made aliasing this field an amplifier - see the query guard in the api
// package, which charges for it accordingly.
func SimulateRisk(ctx context.Context, snap graph.Snapshot, iterations int, seed uint64) (RiskSimulation, error) {
	return SimulateRiskWith(ctx, snap, iterations, seed, RiskOptions{})
}

// SimulateRiskWith is SimulateRisk with a choice of what to compute (RiskOptions). The
// point estimate and the per-jewel figures are the same either way.
func SimulateRiskWith(ctx context.Context, snap graph.Snapshot, iterations int, seed uint64, opt RiskOptions) (RiskSimulation, error) {
	if iterations <= 0 {
		iterations = DefaultRiskIterations
	}
	g := compileGraph(snap)
	sim := RiskSimulation{Iterations: iterations}
	if len(g.seeds) == 0 || len(g.jewels) == 0 {
		return sim, nil // nothing to reach, or nothing to reach from
	}

	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15)) // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
	t := newTrials(g, rng)
	hits := make([]int, len(g.ids))
	anyHits, totalCompromised := 0, 0
	for it := 0; it < iterations; it++ {
		// Checked on a stride rather than every trial: a context check is cheap but not
		// free, and a trial is cheaper still, so testing each one would show up in the
		// hot loop. 256 bounds the overshoot to well under a millisecond.
		if it&(cancelCheckStride-1) == 0 {
			if err := ctx.Err(); err != nil {
				return RiskSimulation{}, err
			}
		}
		t.run(g.p)
		compromised, anyThis := 0, false
		for _, j := range g.jewels {
			if t.reached(j) {
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
	if !opt.PointOnly {
		// Input-uncertainty credible band: resample each edge probability from its Beta
		// posterior and re-run reachability, so the UI can show how much the headline
		// rests on soft inputs - tight where the evidence is strong, wide where it's a
		// guess. Kept in the SensitivityLow/High fields to preserve the API.
		var err error
		sim.SensitivityLow, sim.SensitivityHigh, err = anyCompromiseCredibleBand(ctx, g, seed, sim.AnyCompromiseProbability)
		if err != nil {
			return RiskSimulation{}, err
		}
		// Correlation-aware headline: marginalize the reachability over the attacker-
		// profile mixture, so it's consistent with the per-path mixture score (see the
		// field docs).
		sim.MixtureCompromiseProbability, sim.ProfileCompromise, err = mixtureCompromise(ctx, g, iterations, seed)
		if err != nil {
			return RiskSimulation{}, err
		}
	}
	for _, j := range g.jewels {
		node := g.nodes[g.ids[j]]
		lo, hi := wilson(hits[j], iterations)
		sim.CrownJewels = append(sim.CrownJewels, CrownJewelRisk{
			ID: g.ids[j], Name: node.Name, Label: string(node.Label),
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

// anyCompromiseCredibleBand returns the 5th-95th percentile credible interval on
// P(at least one crown jewel reachable) under input uncertainty. The outer loop
// draws every edge probability from its Beta posterior (concentration set by the
// edge's basis confidence); the inner loop runs `bandInner` reachability trials at
// those drawn probabilities. The spread of the outer any-rates is the band the
// evidence justifies. Deterministic from `seed`. `nominal` is the point estimate,
// used only to guarantee the band brackets it (the reachability function is
// nonlinear, so the resampled mean can drift slightly off the point estimate).
//
// The draws are handed to edges in a fixed order (mcGraph.bandOrder). Ranging over a map
// here once gave every run its own order, and the band came out different on every call
// with the same seed, although `seed` is documented as the way to reproduce it.
func anyCompromiseCredibleBand(ctx context.Context, g *mcGraph, seed uint64, nominal float64) (lo, hi float64, err error) {
	if len(g.seeds) == 0 || len(g.jewels) == 0 {
		return 0, 0, nil
	}
	outerRng := rand.New(rand.NewPCG(seed, 0xa5a5a5a5a5a5a5a5))            // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
	innerRng := rand.New(rand.NewPCG(seed^0x5bd1e995, 0x9e3779b97f4a7c15)) // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
	t := newTrials(g, innerRng)
	sampled := make([]float64, len(g.p))
	rates := make([]float64, bandOuter)
	for o := 0; o < bandOuter; o++ {
		if e := ctx.Err(); e != nil {
			return 0, 0, e
		}
		for _, e := range g.bandOrder {
			a, b := betaParams(g.p[e], g.conf[e], g.evid[e])
			sampled[e] = sampleBeta(outerRng, a, b)
		}
		anyHits := 0
		for it := 0; it < bandInner; it++ {
			t.run(sampled)
			if t.anyJewel() {
				anyHits++
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

// mixtureCompromise marginalizes the any-compromise reachability over the attacker
// profiles: for each profile c it conditions every edge on capability c (p(e|c)) and
// estimates R_c = P(any crown jewel reachable | c), then returns Σ_c P(c)·R_c and the
// per-profile breakdown. Within a profile edges are still sampled independently, but
// conditioning on the shared c introduces the graph-wide positive correlation the
// independent headline drops - the same latent-capability mechanism as the per-path
// mixture, so the two are consistent. Deterministic from `seed`.
func mixtureCompromise(ctx context.Context, g *mcGraph, iterations int, seed uint64) (float64, []ProfileCompromise, error) {
	profs := currentProfiles()
	if iterations <= 0 || len(g.seeds) == 0 || len(g.jewels) == 0 || len(profs) == 0 {
		return 0, nil, nil
	}
	cond := make([]float64, len(g.p))
	out := make([]ProfileCompromise, 0, len(profs))
	mixture := 0.0
	for pi, c := range profs {
		for e := range cond {
			cond[e] = conditionalProb(g.p[e], g.basis[e], c.Skill)
		}
		rng := rand.New(rand.NewPCG(seed^(uint64(pi)+1)*0x9e3779b97f4a7c15, 0xdeadbeefcafef00d)) // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
		t := newTrials(g, rng)
		anyHits := 0
		for it := 0; it < iterations; it++ {
			if it&(cancelCheckStride-1) == 0 {
				if err := ctx.Err(); err != nil {
					return 0, nil, err
				}
			}
			t.run(cond)
			if t.anyJewel() {
				anyHits++
			}
		}
		rc := float64(anyHits) / float64(iterations)
		out = append(out, ProfileCompromise{Profile: c.Name, Prior: c.Prior, Probability: rc})
		mixture += c.Prior * rc
	}
	return mixture, out, nil
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

// cancelCheckStride is how often a Monte Carlo loop looks at its context. A power of two
// so the test is a mask rather than a division.
const cancelCheckStride = 256
