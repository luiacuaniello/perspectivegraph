// Package analyzer turns the graph into ranked attack paths.
//
// An attack path P is a sequence of nodes v₁ → … → vₖ from an internet-exposed
// seed to a crown-jewel target. Each edge carries an exploit probability
// p ∈ (0,1]; the path score is the product S(P) = ∏ p. We convert each edge to
// a cost w = -ln(p) so that maximizing S(P) becomes a shortest-path problem
// (minimizing Σ w), which we solve with Dijkstra from every seed.
//
// The product assumes the hops are independent. When they share a common cause
// (the same weakness gating several steps) they are positively correlated, and
// the product is then a *lower* bound for "all hops succeed"; the comonotonic
// upper bound is the weakest single hop, min p. We expose both (Score and
// ScoreUpperBound) plus a CorrelatedHops flag rather than pretending the point
// estimate is exact - see AttackPath.
package analyzer

import (
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Step is one hop along an attack path.
type Step struct {
	EdgeType    ontology.EdgeType `json:"edge_type"`
	From        string            `json:"from"`
	To          string            `json:"to"`
	Probability float64           `json:"probability"`
	// Identity-resolution provenance for *this hop*: set when the join was
	// inferred by the normalizer (e.g. a container stitched to its image), so a
	// reader can flag - and distrust - a heuristic correlation. Confidence < 1
	// means "verify this link"; it also already discounts Probability above.
	ResolutionMethod     string  `json:"resolution_method,omitempty"`
	ResolutionConfidence float64 `json:"resolution_confidence,omitempty"`
	// WeightBasis records where this hop's probability came from - kev | epss |
	// runtime (evidence) vs cvss | severity | heuristic (estimate) - and
	// WeightConfidence how much to trust it [0,1]. So the score can say which hops
	// rest on observed exploitation and which are educated guesses.
	WeightBasis      string  `json:"weight_basis,omitempty"`
	WeightConfidence float64 `json:"weight_confidence,omitempty"`
	// EvidenceCount is the number of independent observations behind this hop's
	// probability (from the edge's evidence_count), when known. It sets the Beta
	// posterior's concentration directly (evidence-count epistemic uncertainty)
	// instead of the basis-confidence heuristic. 0 ⇒ unknown ⇒ heuristic κ.
	EvidenceCount int `json:"evidence_count,omitempty"`
}

// AttackPath is a scored route from an exposed seed to a crown jewel.
type AttackPath struct {
	ID    string          `json:"id"`
	Score float64         `json:"score"` // S(P) = ∏ p, in (0,1]
	Nodes []ontology.Node `json:"nodes"`
	Steps []Step          `json:"steps"`
	// RuntimeConfirmed is true when some node on the path carries a live Falco
	// runtime alert - the path isn't just reachable, it's being exercised.
	RuntimeConfirmed bool `json:"runtime_confirmed"`
	// Confidence is how much to trust this path's Score given how its edge weights
	// were derived: the mean of the hops' WeightConfidence, in [0,1]. ConfidenceLabel
	// is the qualitative band (high|medium|low) - an honest answer to "why 58%?"
	// that distinguishes an evidence-backed estimate from a pile of severity guesses.
	Confidence      float64 `json:"confidence,omitempty"`
	ConfidenceLabel string  `json:"confidence_label,omitempty"`
	// ScoreUpperBound is the path score if its hops share a common cause instead of
	// being independent: the weakest single hop's probability - the comonotonic
	// (Fréchet) upper bound for "all hops succeed". The headline Score multiplies the
	// hops as if independent, which is a *lower* bound once they are positively
	// correlated, so the true exploitability lies in [Score, ScoreUpperBound]. A wide
	// gap means the independence assumption behind Score is doing a lot of the work.
	ScoreUpperBound float64 `json:"score_upper_bound,omitempty"`
	// CorrelatedHops is true when two or more hops rest on the same weight basis
	// (several heuristic topology defaults, two runtime-confirmed hops, …): a
	// concrete reason the hops may not be independent, so the band above is grounded
	// rather than theoretical. It does not change Score - it tells the reader the
	// product may understate the real risk.
	CorrelatedHops bool `json:"correlated_hops,omitempty"`
	// PosteriorMean, ScoreCILow and ScoreCIHigh are the ONE coherent posterior of the
	// path's success probability: a single Monte Carlo that composes epistemic
	// uncertainty (each hop's probability is a Beta posterior whose width reflects its
	// evidence) with the attacker-capability mixture (Σ_c P(c)·∏ p(e|c), which
	// reintroduces the positive correlation the bare product drops). PosteriorMean is
	// its mean - the coherent point estimate that even corrects the Jensen gap the
	// plug-in MixtureScore ignores - and [ScoreCILow, ScoreCIHigh] is its 90% credible
	// interval, which now brackets that mean rather than the independent product. The
	// four numbers now cohere around one distribution instead of describing different
	// quantities: PosteriorMean sits inside its own interval, and with the default
	// weak-attacker-weighted priors it also stays under ScoreUpperBound (the Fréchet
	// ceiling) - though APT-heavy priors set via ATTACKER_PROFILE_PRIORS can lift the
	// attacker-marginal above it. Being the attacker-*marginal*, it can likewise sit
	// above OR below the bare independent Score depending on the profile priors
	// (weak-attacker-heavy priors pull it below). "55% [38-71%]" ⇒ soft inputs;
	// "55% [52-58%]" ⇒ evidence-backed.
	PosteriorMean float64 `json:"posterior_mean,omitempty"`
	ScoreCILow    float64 `json:"score_ci_low,omitempty"`
	ScoreCIHigh   float64 `json:"score_ci_high,omitempty"`
	// MixtureScore is the deterministic plug-in of the attacker-capability mixture,
	// Σ P(c)·∏ p(e|c) at the point probabilities - the fast closed form; PosteriorMean
	// above is its sampled, epistemic-aware counterpart (the two are close). ProfileScores
	// is the per-profile breakdown - the "72% vs an APT, 18% vs commodity" read - which
	// is what a SOC actually triages on. The naive Score is kept as the independent
	// baseline; these are the correlation-aware lens layered on top.
	MixtureScore  float64        `json:"mixture_score,omitempty"`
	ProfileScores []ProfileScore `json:"profile_scores,omitempty"`
	// Priority is a composite triage score in [0,100] blending the signals an
	// analyst actually weighs - exploitability (Score) and how much to trust it
	// (Confidence), whether it's runtime-confirmed, whether a KEV weakness sits on
	// the route, how sensitive the target is, and the entry's blast radius - so a
	// small team can sort by ONE number and fix the top few instead of triaging
	// every path. PriorityLabel is the band (P1|P2|P3); PriorityFactors are the
	// human-readable reasons (for explainability, like the rest of the scoring).
	Priority        float64  `json:"priority,omitempty"`
	PriorityLabel   string   `json:"priority_label,omitempty"`
	PriorityFactors []string `json:"priority_factors,omitempty"`
}

// Seed and target node of the path, for convenience.
func (p AttackPath) Source() ontology.Node { return p.Nodes[0] }
func (p AttackPath) Target() ontology.Node { return p.Nodes[len(p.Nodes)-1] }

// pathWorkers configures how many goroutines fan out the per-seed shortest-path
// searches in FindCriticalPaths. Each internet-exposed seed gets an independent
// Dijkstra over the same immutable adjacency, so the work parallelizes cleanly
// across cores - the dominant per-pass cost on a large graph with many entry
// points. 0 (the default) means "auto" = GOMAXPROCS. Set once at startup from
// ANALYZER_WORKERS via SetPathWorkers; atomic so a benchmark can vary it safely.
var pathWorkers atomic.Int64

// SetPathWorkers configures the per-seed pathfinding parallelism. n <= 0 selects
// the automatic default (GOMAXPROCS). Safe to call concurrently.
func SetPathWorkers(n int) {
	if n < 0 {
		n = 0
	}
	pathWorkers.Store(int64(n))
}

// resolvedWorkers caps the configured worker count to something useful for this
// pass: never more than the number of seeds (extra goroutines would idle), never
// less than 1, and "auto" resolves to GOMAXPROCS.
func resolvedWorkers(seeds int) int {
	w := int(pathWorkers.Load())
	if w <= 0 {
		w = runtime.GOMAXPROCS(0)
	}
	if w > seeds {
		w = seeds
	}
	if w < 1 {
		w = 1
	}
	return w
}

// FindCriticalPaths returns, for every (seed, crown-jewel) pair that is
// reachable, the single highest-probability path, sorted by score descending.
//
// The per-seed Dijkstra searches are independent reads over a shared, immutable
// adjacency, so they fan out across a bounded worker pool (see pathWorkers). The
// result is assembled in seed order before the final sort, so the output is
// byte-for-byte identical to a sequential run regardless of how many workers ran
// - parallelism is a speedup, never a behavior change.
func FindCriticalPaths(snap graph.Snapshot) []AttackPath {
	nodes := snap.NodeByID()
	adj := buildAdjacency(snap.Edges, nodes)

	var seeds, jewels []string
	for _, n := range snap.Nodes {
		// A path may originate from internet exposure (the default) or, when the operator
		// opts in, from a credential-origin seed (an identity whose creds could leak).
		if n.Bool(ontology.PropInternetExposed) || n.Bool(ontology.PropCredentialExposed) {
			seeds = append(seeds, n.ID)
		}
		if n.Bool(ontology.PropCrownJewel) {
			jewels = append(jewels, n.ID)
		}
	}
	if len(seeds) == 0 || len(jewels) == 0 {
		return nil
	}

	// One result bucket per seed, filled in place so the flattened order matches
	// the original sequential nested loop (and thus the post-sort output) exactly.
	perSeed := make([][]AttackPath, len(seeds))
	if workers := resolvedWorkers(len(seeds)); workers <= 1 {
		for i, seed := range seeds {
			perSeed[i] = pathsFromSeed(seed, jewels, adj, nodes)
		}
	} else {
		var wg sync.WaitGroup
		work := make(chan int)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range work {
					perSeed[i] = pathsFromSeed(seeds[i], jewels, adj, nodes)
				}
			}()
		}
		for i := range seeds {
			work <- i
		}
		close(work)
		wg.Wait()
	}

	var paths []AttackPath
	for _, ps := range perSeed {
		paths = append(paths, ps...)
	}

	// Runtime-confirmed paths first, then by score descending.
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].RuntimeConfirmed != paths[j].RuntimeConfirmed {
			return paths[i].RuntimeConfirmed
		}
		return paths[i].Score > paths[j].Score
	})
	return paths
}

// pathsFromSeed runs one seed's Dijkstra and reconstructs the best route to every
// reachable jewel. It owns its dist/prev maps and only reads the shared adjacency
// and node index, so many of these run concurrently without coordination.
func pathsFromSeed(seed string, jewels []string, adj map[string][]outEdge, nodes map[string]ontology.Node) []AttackPath {
	dist, prev := dijkstra(seed, adj)
	var out []AttackPath
	for _, jewel := range jewels {
		if seed == jewel {
			continue
		}
		d, ok := dist[jewel]
		if !ok || math.IsInf(d, 1) {
			continue // unreachable
		}
		out = append(out, reconstruct(seed, jewel, prev, nodes))
	}
	return out
}

// dbPathTimeout bounds a DB-side path query from the client side, on top of the
// store's own statement_timeout, so a pathological variable-length enumeration
// can never hang the analyzer - it deadlines and falls back to Dijkstra.
const dbPathTimeout = 10 * time.Second

// CriticalPathsVia returns ranked critical paths. By default it uses the
// in-process Dijkstra over the snapshot - a polynomial, bounded algorithm that is
// the right engine for the per-pass "all paths" computation. When useDB is set
// and the store supports it (graph.PathStore - AGE, via a Cypher variable-length
// match), it computes them in the database instead, but defensively: a tight
// timeout means a runaway enumeration falls back to Dijkstra rather than hanging.
func CriticalPathsVia(ctx context.Context, store graph.Store, snap graph.Snapshot, maxHops int, useDB bool) []AttackPath {
	if useDB {
		if pf, ok := graph.AsPathStore(store); ok {
			qctx, cancel := context.WithTimeout(ctx, dbPathTimeout)
			defer cancel()
			if raws, err := pf.CriticalPaths(qctx, maxHops); err == nil {
				return rankRawPaths(raws)
			} else {
				slog.Warn("db pathfinder failed/timed out, falling back to in-process Dijkstra", "err", err)
			}
		}
	}
	return FindCriticalPaths(snap)
}

// rankRawPaths scores raw DB paths, keeps the highest-probability one per
// (source, target), and sorts them like FindCriticalPaths (runtime-confirmed
// first, then score descending).
func rankRawPaths(raws []graph.RawPath) []AttackPath {
	best := map[string]AttackPath{}
	for _, rp := range raws {
		ap, ok := attackPathFromRaw(rp)
		if !ok {
			continue
		}
		key := ap.Source().ID + "\x00" + ap.Target().ID
		if cur, exists := best[key]; !exists || ap.Score > cur.Score {
			best[key] = ap
		}
	}
	out := make([]AttackPath, 0, len(best))
	for _, ap := range best {
		out = append(out, ap)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RuntimeConfirmed != out[j].RuntimeConfirmed {
			return out[i].RuntimeConfirmed
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func attackPathFromRaw(rp graph.RawPath) (AttackPath, bool) {
	if len(rp.Nodes) < 2 || len(rp.Edges) != len(rp.Nodes)-1 {
		return AttackPath{}, false
	}
	steps := make([]Step, 0, len(rp.Edges))
	for i, e := range rp.Edges {
		p := clampProb(e.ExploitProbability)
		method, conf := resolutionOf(e.Properties)
		basis, basisConf, evid := weightBasisOf(e, rp.Nodes[i], rp.Nodes[i+1])
		steps = append(steps, Step{EdgeType: e.Type, From: e.From, To: e.To, Probability: p, ResolutionMethod: method, ResolutionConfidence: conf, WeightBasis: basis, WeightConfidence: basisConf, EvidenceCount: evid})
	}
	return assembleAttackPath(rp.Nodes, steps), true
}

// clampProb keeps an edge probability in the (0,1] the scoring assumes: a missing
// or non-positive weight stays traversable but costly rather than making -ln(p)
// infinite, and anything above 1 is a bad input, not a certainty.
func clampProb(p float64) float64 {
	if p <= 0 {
		return 0.01
	}
	if p > 1 {
		return 1
	}
	return p
}

// assembleAttackPath is the ONE place a scored AttackPath is built from its
// ordered nodes and steps. Both entry points funnel through it - the in-process
// Dijkstra (reconstruct) and the database pathfinder (attackPathFromRaw) - so the
// score, the correlation bound, the confidence, the posterior and the mixture can
// never silently drift apart between the two. Callers own only the shape-specific
// work: turning their own representation into (nodes, steps).
func assembleAttackPath(nodes []ontology.Node, steps []Step) AttackPath {
	if len(nodes) == 0 {
		return AttackPath{}
	}
	score := 1.0
	minP := 1.0 // weakest hop → the comonotonic (shared-cause) upper bound on the path
	for _, st := range steps {
		score *= st.Probability
		if st.Probability < minP {
			minP = st.Probability
		}
	}
	runtime := false
	for _, n := range nodes {
		if n.Bool(ontology.PropRuntimeAlert) {
			runtime = true
			break
		}
	}
	conf, label := pathConfidence(steps)
	id := fmt.Sprintf("ap-%s-%s", shortID(nodes[0].ID), shortID(nodes[len(nodes)-1].ID))
	postMean, ciLo, ciHi := unifiedScorePosterior(id, steps, currentProfiles(), score)
	mix, profs := attackerMixture(steps)
	return AttackPath{
		ID:               id,
		Score:            score,
		Nodes:            nodes,
		Steps:            steps,
		RuntimeConfirmed: runtime,
		Confidence:       conf,
		ConfidenceLabel:  label,
		ScoreUpperBound:  minP,
		CorrelatedHops:   hopsCorrelated(steps),
		PosteriorMean:    postMean,
		ScoreCILow:       ciLo,
		ScoreCIHigh:      ciHi,
		MixtureScore:     mix,
		ProfileScores:    profs,
	}
}

// hopsCorrelated reports whether the path leans on a repeated weight basis - the
// concrete, data-driven signal that its hops may share a common cause and so
// violate the independence the product score assumes. Two hops resting on the
// same basis (e.g. two heuristic topology defaults, or two runtime-confirmed
// hops) are the realistic correlation; a single hop, or all-distinct bases,
// leaves the product defensible. This is a deliberately conservative proxy: it
// never inflates Score, it only flags when the [Score, ScoreUpperBound] band is
// worth reading.
func hopsCorrelated(steps []Step) bool {
	if len(steps) < 2 {
		return false
	}
	seen := make(map[string]int, len(steps))
	for _, s := range steps {
		if s.WeightBasis == "" {
			continue
		}
		seen[s.WeightBasis]++
		if seen[s.WeightBasis] >= 2 {
			return true
		}
	}
	return false
}

// ── Dijkstra ────────────────────────────────────────────────────────

type outEdge struct {
	to        string
	typ       ontology.EdgeType
	weight    float64 // -ln(p)
	prob      float64
	resMethod string
	resConf   float64
	basis     string  // provenance of `prob` (kev|epss|runtime|cvss|severity|heuristic)
	basisConf float64 // how much to trust `prob`, [0,1]
	evid      int     // independent observations behind `prob` (0 = unknown)
}

// weightBasisOf classifies where an edge's exploit probability came from and how
// much to trust it. Threat-intel stamps kev/epss directly; otherwise we infer:
// a runtime-confirmed endpoint is observed evidence, a vuln edge with a CVSS
// score is severity-derived but anchored, a bare severity label is a guess, and
// everything else (topology/identity defaults) is an assumed heuristic.
func weightBasisOf(e ontology.Edge, from, to ontology.Node) (string, float64, int) {
	n := evidenceCountOf(e)
	if b, ok := e.Properties[ontology.PropWeightBasis].(string); ok && b != "" {
		return b, basisConfidence(b), n
	}
	if from.Bool(ontology.PropRuntimeAlert) || to.Bool(ontology.PropRuntimeAlert) {
		return "runtime", basisConfidence("runtime"), n
	}
	switch e.Type {
	case ontology.EdgeAffects, ontology.EdgeExploits:
		if to.Properties[ontology.PropCVSS] != nil || from.Properties[ontology.PropCVSS] != nil {
			return "cvss", basisConfidence("cvss"), n
		}
		return "severity", basisConfidence("severity"), n
	default:
		return "heuristic", basisConfidence("heuristic"), n
	}
}

// evidenceCountOf reads an edge's evidence_count (independent observations behind its
// probability) as a non-negative int - 0 when absent or malformed. Handles the numeric
// shapes a property can arrive as (int from the in-memory store, float64/json.Number
// from a JSON/AGE round-trip).
func evidenceCountOf(e ontology.Edge) int {
	switch v := e.Properties[ontology.PropEvidenceCount].(type) {
	case int:
		if v > 0 {
			return v
		}
	case int64:
		if v > 0 {
			return int(v)
		}
	case float64:
		if v > 0 {
			return int(v)
		}
	case json.Number:
		if n, err := v.Int64(); err == nil && n > 0 {
			return int(n)
		}
	}
	return 0
}

// basisConfidence maps a weight's provenance to how much to trust it. Observed
// exploitation (kev/runtime) tops the scale; data-driven prediction (epss) is
// close; a CVSS-anchored guess is middling; a bare severity label or an assumed
// topology default is low - the honest discount on invented probabilities.
func basisConfidence(basis string) float64 {
	switch basis {
	case "kev":
		return 0.95
	case "runtime":
		return 0.9
	case "epss":
		return 0.85
	case "cvss":
		return 0.6
	case "severity":
		return 0.4
	case "heuristic":
		return 0.35
	default:
		return 0.3
	}
}

// pathConfidence summarizes how trustworthy a path's score is from its hops'
// weight provenance: the mean hop confidence, plus a qualitative band so a CISO
// gets "55%, low confidence" rather than false precision.
func pathConfidence(steps []Step) (float64, string) {
	if len(steps) == 0 {
		return 0, ""
	}
	sum := 0.0
	for _, st := range steps {
		sum += st.WeightConfidence
	}
	c := sum / float64(len(steps))
	switch {
	case c >= 0.7:
		return c, "high"
	case c >= 0.45:
		return c, "medium"
	default:
		return c, "low"
	}
}

func buildAdjacency(edges []ontology.Edge, nodes map[string]ontology.Node) map[string][]outEdge {
	adj := make(map[string][]outEdge)
	for _, e := range edges {
		p := clampProb(e.ExploitProbability)
		method, conf := resolutionOf(e.Properties)
		basis, basisConf, evid := weightBasisOf(e, nodes[e.From], nodes[e.To])
		adj[e.From] = append(adj[e.From], outEdge{
			to:        e.To,
			typ:       e.Type,
			weight:    -math.Log(p),
			prob:      p,
			resMethod: method,
			resConf:   conf,
			basis:     basis,
			basisConf: basisConf,
			evid:      evid,
		})
	}
	return adj
}

// resolutionOf extracts identity-resolution provenance from an edge's property
// bag, tolerating the numeric types both graph stores hand back (memory: float64;
// AGE agtype: float64/json.Number/int). Returns ("", 0) when the join wasn't
// inferred - the common case for hard, tool-asserted edges.
func resolutionOf(props map[string]any) (method string, confidence float64) {
	if props == nil {
		return "", 0
	}
	method, _ = props[ontology.PropResolutionMethod].(string)
	switch v := props[ontology.PropResolutionConfidence].(type) {
	case float64:
		confidence = v
	case float32:
		confidence = float64(v)
	case int:
		confidence = float64(v)
	case int64:
		confidence = float64(v)
	}
	return method, confidence
}

func dijkstra(src string, adj map[string][]outEdge) (dist map[string]float64, prev map[string]Step) {
	dist = map[string]float64{src: 0}
	prev = map[string]Step{}
	pq := &minHeap{{node: src, d: 0}}

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(heapItem)
		if cur.d > dist[cur.node] {
			continue // stale entry
		}
		for _, e := range adj[cur.node] {
			nd := cur.d + e.weight
			if old, ok := dist[e.to]; !ok || nd < old {
				dist[e.to] = nd
				prev[e.to] = Step{EdgeType: e.typ, From: cur.node, To: e.to, Probability: e.prob, ResolutionMethod: e.resMethod, ResolutionConfidence: e.resConf, WeightBasis: e.basis, WeightConfidence: e.basisConf, EvidenceCount: e.evid}
				heap.Push(pq, heapItem{node: e.to, d: nd})
			}
		}
	}
	return dist, prev
}

func reconstruct(seed, jewel string, prev map[string]Step, nodes map[string]ontology.Node) AttackPath {
	var steps []Step
	for at := jewel; at != seed; {
		st := prev[at]
		steps = append(steps, st)
		at = st.From
	}
	// steps are jewel→seed; reverse to seed→jewel.
	for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
		steps[i], steps[j] = steps[j], steps[i]
	}

	pathNodes := make([]ontology.Node, 0, len(steps)+1)
	pathNodes = append(pathNodes, nodes[seed])
	for _, st := range steps {
		pathNodes = append(pathNodes, nodes[st.To])
	}
	return assembleAttackPath(pathNodes, steps)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[len(id)-12:]
	}
	return id
}

// ── priority queue ──────────────────────────────────────────────────

type heapItem struct {
	node string
	d    float64
}

type minHeap []heapItem

func (h minHeap) Len() int           { return len(h) }
func (h minHeap) Less(i, j int) bool { return h[i].d < h[j].d }
func (h minHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *minHeap) Push(x any)        { *h = append(*h, x.(heapItem)) }
func (h *minHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}
