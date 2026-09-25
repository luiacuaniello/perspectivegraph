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
// probability p), then asks: is the crown jewel reachable from any seed in this
// realized graph? The fraction of trials where it is reachable is an unbiased
// estimate of its compromise probability, correlations and all.
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
//
// Common random numbers. Every draw is a pure function of the seed, the trial and the
// edge it decides - a hash of the edge's endpoints and type, not its position in the
// snapshot. Two graphs that share an edge therefore share its fate in every trial, which
// is what makes a comparison between them mean something:
//
//   - A what-if runs the same trials over the graph before and after a cut. The cut can
//     only take edges away, so no trial reaches more afterwards: the reduction is never
//     negative, and it is exactly zero for an edge no route to a jewel ever crosses. The
//     draws used to come off one sequential stream instead, and removing any edge shifted
//     every draw after it - so the two runs were independent samples, their difference
//     was noise of ±2.5 points at 800 trials, and a fix's "verified" was granted by that
//     noise about half the time, for a cut that did nothing at all.
//   - The credible band runs its inner trials on the same draws for every posterior
//     sample. Its spread is then the spread the inputs cause, not the binomial noise of
//     400 trials: an edge known to within a hair used to show a band of ±4 points.
//   - The attacker profiles face the same draws, so a stronger attacker never reaches
//     less than a weaker one in any trial.
//
// It also makes a result independent of the order the store returns edges in.

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
type mcGraph struct {
	nodes map[string]ontology.Node
	ids   []string
	index map[string]int32

	seeds  []int32
	jewels []int32 // in node order, each once
	// byEdgeOnly marks a crown jewel that is also a seed without being held: it can be
	// reached from the internet - an attack may start there - but reachable is not
	// compromised, so it counts only when an edge reaches it. A held jewel (open to
	// anyone, or credentials assumed leaked) counts in every trial. See
	// ontology.Node.HeldByAttacker.
	byEdgeOnly []bool

	adj   [][]int32 // per source node, its edges in snapshot order
	to    []int32
	key   []uint64 // what decides the edge's fate in a trial: its cause's key, or its own
	p     []float64
	conf  []float64
	basis []string
	evid  []int
}

// edgeKey names an edge by what it is - endpoints and type - so the same edge has the
// same key in every snapshot that holds it, wherever the store lists it. Two edges
// with the same endpoints and type are one relationship reported twice, and share
// their fate.
func edgeKey(e ontology.Edge) uint64 {
	return mix64(fnv64(e.From, e.To, string(e.Type)))
}

// causeKey names a shared weight cause. Every edge resting on it takes this key, so
// they share one draw per trial: the Fréchet coupling where P(all edges of a cause
// succeed) = min p rather than ∏p - the common-cause correlation independent sampling
// misses (several paths that all rest on the same CVE are not independent redundancy).
func causeKey(name string) uint64 {
	return mix64(fnv64("cause", name))
}

// fnv64 is FNV-1a over the parts, each followed by a zero byte so that ("ab","c") and
// ("a","bc") differ.
func fnv64(parts ...string) uint64 {
	const offset, prime = 14695981039346656037, 1099511628211
	h := uint64(offset)
	for _, s := range parts {
		for i := 0; i < len(s); i++ {
			h ^= uint64(s[i])
			h *= prime
		}
		h *= prime // the separator: h ^= 0 is a no-op
	}
	return h
}

// mix64 is the splitmix64 finalizer: a bijection on 64 bits in which every input bit
// moves about half the output bits.
func mix64(z uint64) uint64 {
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// unit maps 64 random bits to a uniform in [0,1), with the 53 bits a float64 holds.
func unit(x uint64) float64 { return float64(x>>11) * 0x1p-53 }

// Streams keep the draws of different jobs apart. The headline and the attacker
// profiles share one on purpose: a profile faces the same trials as the headline.
const (
	streamTrials uint64 = iota // the headline's trials, and each profile's
	streamBand                 // the credible band's inner trials
	streamBeta                 // the credible band's posterior draws
)

// trialKey is the key of one trial - or, for streamBeta, of one posterior sample. Every
// draw in it is a function of this key and an edge or cause key.
func trialKey(seed, stream, outer, trial uint64) uint64 {
	h := mix64(seed + (stream+1)*0x9e3779b97f4a7c15)
	h = mix64(h + (outer+1)*0xbf58476d1ce4e5b9)
	return mix64(h + (trial+1)*0x94d049bb133111eb)
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
	for _, e := range snap.Edges {
		from, to := id(e.From), id(e.To)
		// Weight provenance (kev/runtime/epss/cvss/severity/heuristic): the confidence
		// sets how much the credible band lets this edge move; the basis drives p(e|c)
		// for the per-profile mixture - both shared with the per-path scoring.
		basis, conf, evid := weightBasisOf(e, g.nodes[e.From], g.nodes[e.To])
		k := edgeKey(e)
		if name, _ := e.Properties[ontology.PropWeightCause].(string); name != "" {
			k = causeKey(name)
		}
		eid := int32(len(g.to)) // #nosec G115 -- edge count is far below 2^31
		g.to = append(g.to, to)
		g.key = append(g.key, k)
		g.p = append(g.p, clampProb(e.ExploitProbability))
		g.conf = append(g.conf, conf)
		g.basis = append(g.basis, basis)
		g.evid = append(g.evid, evid)
		g.adj[from] = append(g.adj[from], eid)
	}
	g.byEdgeOnly = make([]bool, len(g.ids))
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
		node := g.nodes[n.ID]
		seed := node.IsSeed()
		if seed {
			g.seeds = append(g.seeds, i)
		}
		if node.Bool(ontology.PropCrownJewel) {
			g.jewels = append(g.jewels, i)
			g.byEdgeOnly[i] = seed && !node.HeldByAttacker()
		}
	}
	return g
}

// trials runs reachability trials over a compiled graph. visited and hit are stamped
// with a generation instead of cleared, so starting a trial costs nothing.
type trials struct {
	g       *mcGraph
	key     uint64 // the running trial's key
	gen     uint32
	visited []uint32
	hit     []uint32 // a byEdgeOnly jewel an edge reached in this trial
	stack   []int32
}

func newTrials(g *mcGraph) *trials {
	return &trials{g: g, visited: make([]uint32, len(g.ids)), hit: make([]uint32, len(g.ids))}
}

// run is one trial: a DFS from the seeds that crosses an edge when the edge's draw in
// this trial falls under prob[edge]. The draw is keyed by the trial and the edge (or its
// cause), not taken off a stream, so it does not depend on which edges the graph holds
// or the order the walk meets them.
func (t *trials) run(key uint64, prob []float64) {
	t.key = key
	t.gen++
	if t.gen == 0 { // wrapped after 2^32 trials: the stamps are ambiguous, start over
		clear(t.visited)
		clear(t.hit)
		t.gen = 1
	}
	g := t.g
	stack := t.stack[:0]
	for _, s := range g.seeds {
		if t.visited[s] != t.gen {
			t.visited[s] = t.gen
			stack = append(stack, s)
		}
	}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, e := range g.adj[cur] {
			to := g.to[e]
			if to == cur {
				continue // a self-loop reaches nothing new
			}
			seen := t.visited[to] == t.gen
			// A node already reached is done with - unless it is a jewel that only an edge
			// can compromise and none has yet.
			if seen && !(g.byEdgeOnly[to] && t.hit[to] != t.gen) {
				continue
			}
			if unit(mix64(t.key^g.key[e])) >= prob[e] {
				continue
			}
			if g.byEdgeOnly[to] {
				t.hit[to] = t.gen
			}
			if !seen {
				t.visited[to] = t.gen
				stack = append(stack, to)
			}
		}
	}
	t.stack = stack
}

// reached reports whether the last trial compromised node j.
func (t *trials) reached(j int32) bool {
	if t.g.byEdgeOnly[j] {
		return t.hit[j] == t.gen
	}
	return t.visited[j] == t.gen
}

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
	// of a simulation's cost - 26,000 band trials and three mixture runs, against 800
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

	t := newTrials(g)
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
		t.run(trialKey(seed, streamTrials, 0, uint64(it)), g.p) // #nosec G115 -- it is non-negative
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
// evidence justifies. Deterministic from `seed`. `nominal` is the point estimate.
//
// The inner trials are the same for every posterior sample (common random numbers), so
// the outer rates differ only by what the drawn probabilities change - no binomial
// noise between them. What they still share is the noise of their level: 400 trials
// put every rate up to a few points off, together. So the band is measured against a
// control run on the same trials at the point probabilities, and laid around the
// headline: lo = nominal + (q05 - control), hi = nominal + (q95 - control). The shared
// error cancels in the difference, and the asymmetry the inputs cause - reachability is
// nonlinear, so the posterior can lean to one side of the point estimate - is kept.
//
// Each posterior draw is keyed by the sample and the edge, like the trials, so the band
// does not depend on the order the snapshot lists edges in either.
func anyCompromiseCredibleBand(ctx context.Context, g *mcGraph, seed uint64, nominal float64) (lo, hi float64, err error) {
	if len(g.seeds) == 0 || len(g.jewels) == 0 {
		return 0, 0, nil
	}
	t := newTrials(g)
	rate := func(prob []float64) float64 {
		anyHits := 0
		for it := 0; it < bandInner; it++ {
			t.run(trialKey(seed, streamBand, 0, uint64(it)), prob) // #nosec G115 -- it is non-negative
			if t.anyJewel() {
				anyHits++
			}
		}
		return float64(anyHits) / float64(bandInner)
	}
	control := rate(g.p)

	src := rand.NewPCG(0, 0)
	rng := rand.New(src) // #nosec G404 -- deterministic PRNG for reproducible Monte Carlo, not security-sensitive
	sampled := make([]float64, len(g.p))
	rates := make([]float64, bandOuter)
	for o := 0; o < bandOuter; o++ {
		if e := ctx.Err(); e != nil {
			return 0, 0, e
		}
		sample := trialKey(seed, streamBeta, uint64(o), 0) // #nosec G115 -- o is non-negative
		for e := range sampled {
			src.Seed(sample, g.key[e])
			a, b := betaParams(g.p[e], g.conf[e], g.evid[e])
			sampled[e] = sampleBeta(rng, a, b)
		}
		rates[o] = rate(sampled)
	}
	sort.Float64s(rates)
	lo = nominal + rates[pctIndex(0.05, bandOuter)] - control
	hi = nominal + rates[pctIndex(0.95, bandOuter)] - control
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
// mixture, so the two are consistent. Every profile runs the headline's trials, so a
// more capable attacker never reaches less. Deterministic from `seed`.
func mixtureCompromise(ctx context.Context, g *mcGraph, iterations int, seed uint64) (float64, []ProfileCompromise, error) {
	profs := currentProfiles()
	if iterations <= 0 || len(g.seeds) == 0 || len(g.jewels) == 0 || len(profs) == 0 {
		return 0, nil, nil
	}
	// Every edge's probability for every profile, anchored so the profiles average back
	// to the edge's own probability (see profiles.go): byProfile[c][e].
	byProfile := make([][]float64, len(profs))
	for c := range byProfile {
		byProfile[c] = make([]float64, len(g.p))
	}
	probs := make([]float64, len(profs))
	for e := range g.p {
		profileProbs(g.p[e], g.basis[e], profs, probs)
		for c := range byProfile {
			byProfile[c][e] = probs[c]
		}
	}
	out := make([]ProfileCompromise, 0, len(profs))
	mixture := 0.0
	t := newTrials(g)
	for ci, c := range profs {
		cond := byProfile[ci]
		anyHits := 0
		for it := 0; it < iterations; it++ {
			if it&(cancelCheckStride-1) == 0 {
				if err := ctx.Err(); err != nil {
					return 0, nil, err
				}
			}
			t.run(trialKey(seed, streamTrials, 0, uint64(it)), cond) // #nosec G115 -- it is non-negative
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
