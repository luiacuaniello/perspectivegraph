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
//   - a *sensitivity band* re-runs the simulation with every edge probability
//     scaled ±30% and reports the resulting spread. The per-edge probabilities
//     are heuristic (a severity→p table), so this is the more important honesty:
//     it shows how much the headline depends on those soft inputs. A tight band
//     means trust the number; a wide one means treat it qualitatively.

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

// Sensitivity band: how far the heuristic per-edge probabilities are perturbed
// to gauge the headline's dependence on those soft inputs (±30%).
const (
	sensitivityScaleDown = 0.7
	sensitivityScaleUp   = 1.3
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
}

type probEdge struct {
	to string
	p  float64
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
		adj[e.From] = append(adj[e.From], probEdge{to: e.To, p: p})
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

	for it := 0; it < iterations; it++ {
		clear(visited)
		// Reachability over the realized graph. Each directed edge is sampled
		// exactly once per trial (its tail node is popped once), which is
		// equivalent to pre-realizing every edge but cheaper.
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
				if rng.Float64() <= e.p { // edge is present in this realization
					visited[e.to] = true
					stack = append(stack, e.to)
				}
			}
		}

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
	// Input-sensitivity band: re-run the any-compromise estimate with edge
	// probabilities scaled down/up, so the UI can show how much the headline
	// rests on the heuristic inputs.
	sim.SensitivityLow = anyCompromiseRate(seeds, jewels, adj, iterations, seed, sensitivityScaleDown)
	sim.SensitivityHigh = anyCompromiseRate(seeds, jewels, adj, iterations, seed, sensitivityScaleUp)
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

// anyCompromiseRate estimates P(at least one crown jewel reachable) with every
// edge probability multiplied by `scale` (clamped to [0,1]). Used to build the
// sensitivity band; it tallies only the any-compromise outcome, so it is cheaper
// than the full per-jewel pass.
func anyCompromiseRate(seeds, jewels []string, adj map[string][]probEdge, iterations int, seed uint64, scale float64) float64 {
	if iterations <= 0 || len(seeds) == 0 || len(jewels) == 0 {
		return 0
	}
	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	visited := map[string]bool{}
	anyHits := 0
	for it := 0; it < iterations; it++ {
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
				pp := e.p * scale
				if pp > 1 {
					pp = 1
				}
				if rng.Float64() <= pp {
					visited[e.to] = true
					stack = append(stack, e.to)
				}
			}
		}
		for _, j := range jewels {
			if visited[j] {
				anyHits++
				break
			}
		}
	}
	return float64(anyHits) / float64(iterations)
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
