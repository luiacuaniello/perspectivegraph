package analyzer

// K-shortest paths (Yen's algorithm) and what-if simulation.
//
// FindCriticalPaths returns the single best route per (seed, jewel). But cutting
// that one edge rarely closes the exposure: there are usually *several* near-best
// routes, and an honest remediation conversation needs to see them. Yen's
// algorithm enumerates the top-K loopless paths in order of decreasing
// probability, built on the same Dijkstra/-ln(p) machinery.
//
// What-if then asks the inverse: given a set of edges we intend to cut (fix),
// what do the surviving paths and the quantified risk look like? It re-runs the
// analyzer and the Monte Carlo simulation on the pruned graph, using common
// random numbers so the before/after risk delta reflects the cut, not noise (see
// montecarlo.go).

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// wgraph is a simple-graph view for path enumeration: parallel edges between the
// same ordered pair collapse to the highest-probability one, so a node sequence
// names exactly one path (the strongest route through those nodes).
type wgraph struct {
	adj   map[string]map[string]outEdge
	nodes map[string]ontology.Node
}

func newWGraph(snap graph.Snapshot) *wgraph {
	g := &wgraph{adj: map[string]map[string]outEdge{}, nodes: snap.NodeByID()}
	for _, e := range snap.Edges {
		p := clampProb(e.ExploitProbability)
		method, conf := resolutionOf(e.Properties)
		basis, basisConf, evid := weightBasisOf(e, g.nodes[e.From], g.nodes[e.To])
		oe := outEdge{to: e.To, typ: e.Type, weight: -math.Log(p), prob: p, resMethod: method, resConf: conf,
			basis: basis, basisConf: basisConf, evid: evid, cause: weightCauseOf(e)}
		m := g.adj[e.From]
		if m == nil {
			m = map[string]outEdge{}
			g.adj[e.From] = m
		}
		if cur, ok := m[e.To]; !ok || oe.weight < cur.weight {
			m[e.To] = oe
		}
	}
	return g
}

// neighbors returns cur's out-edges in a deterministic order (weight, then id)
// so path enumeration and tie-breaking are reproducible.
func (g *wgraph) neighbors(cur string) []outEdge {
	m := g.adj[cur]
	out := make([]outEdge, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].weight != out[j].weight {
			return out[i].weight < out[j].weight
		}
		return out[i].to < out[j].to
	})
	return out
}

// shortest runs Dijkstra from src to dst over the graph minus removedNodes and
// removedEdges, returning the node sequence and its total cost.
func (g *wgraph) shortest(src, dst string, removedNodes map[string]bool, removedEdges map[[2]string]bool) ([]string, float64, bool) {
	if removedNodes[src] || removedNodes[dst] {
		return nil, 0, false
	}
	dist := map[string]float64{src: 0}
	prev := map[string]string{}
	pq := &minHeap{{node: src, d: 0}}

	for pq.Len() > 0 {
		cur := pq.pop()
		if cur.d > dist[cur.node] {
			continue
		}
		for _, e := range g.neighbors(cur.node) {
			if removedNodes[e.to] || removedEdges[[2]string{cur.node, e.to}] {
				continue
			}
			nd := cur.d + e.weight
			if old, ok := dist[e.to]; !ok || nd < old {
				dist[e.to] = nd
				prev[e.to] = cur.node
				pq.push(heapItem{node: e.to, d: nd})
			}
		}
	}

	d, ok := dist[dst]
	if !ok || math.IsInf(d, 1) {
		return nil, 0, false
	}
	seq := []string{dst}
	for at := dst; at != src; {
		p, ok := prev[at]
		if !ok {
			return nil, 0, false
		}
		seq = append(seq, p)
		at = p
	}
	for i, j := 0, len(seq)-1; i < j; i, j = i+1, j-1 {
		seq[i], seq[j] = seq[j], seq[i]
	}
	return seq, d, true
}

type candPath struct {
	nodes []string
	cost  float64
}

// kShortest implements Yen's algorithm: up to k loopless src→dst paths, ascending
// in cost (descending in probability).
func (g *wgraph) kShortest(src, dst string, k int) []candPath {
	if k <= 0 {
		k = 1
	}
	first, c0, ok := g.shortest(src, dst, nil, nil)
	if !ok {
		return nil
	}
	a := []candPath{{first, c0}}
	var b []candPath

	for len(a) < k {
		prev := a[len(a)-1].nodes
		for i := 0; i < len(prev)-1; i++ {
			spur := prev[i]
			root := prev[:i+1]

			removedEdges := map[[2]string]bool{}
			for _, p := range a {
				if len(p.nodes) > i && equalPrefix(p.nodes, root) {
					removedEdges[[2]string{p.nodes[i], p.nodes[i+1]}] = true
				}
			}
			removedNodes := map[string]bool{}
			for _, n := range root[:len(root)-1] { // keep the spur node itself
				removedNodes[n] = true
			}

			spurNodes, _, ok := g.shortest(spur, dst, removedNodes, removedEdges)
			if !ok {
				continue
			}
			total := append(append([]string(nil), root[:len(root)-1]...), spurNodes...)
			cost, ok := g.pathCost(total)
			if !ok {
				continue
			}
			cp := candPath{total, cost}
			if !containsPath(a, cp) && !containsPath(b, cp) {
				b = append(b, cp)
			}
		}
		if len(b) == 0 {
			break
		}
		sort.Slice(b, func(i, j int) bool {
			if b[i].cost != b[j].cost {
				return b[i].cost < b[j].cost
			}
			return pathKey(b[i].nodes) < pathKey(b[j].nodes)
		})
		a = append(a, b[0])
		b = b[1:]
	}
	return a
}

func (g *wgraph) pathCost(seq []string) (float64, bool) {
	cost := 0.0
	for i := 0; i+1 < len(seq); i++ {
		e, ok := g.adj[seq[i]][seq[i+1]]
		if !ok {
			return 0, false
		}
		cost += e.weight
	}
	return cost, true
}

// toAttackPath materializes a node sequence into a scored AttackPath - through
// assembleAttackPath, like every other path. It used to score the route itself, and an
// alternative route came back without its interval, its mixture, its upper bound or the
// provenance of its joins: the same route read differently depending on which list
// showed it.
func (g *wgraph) toAttackPath(seq []string) AttackPath {
	pathNodes := make([]ontology.Node, 0, len(seq))
	var steps []Step
	for i, id := range seq {
		pathNodes = append(pathNodes, g.nodes[id])
		if i+1 < len(seq) {
			e := g.adj[id][seq[i+1]]
			steps = append(steps, Step{EdgeType: e.typ, From: id, To: seq[i+1], Probability: e.prob,
				ResolutionMethod: e.resMethod, ResolutionConfidence: e.resConf, WeightBasis: e.basis,
				WeightConfidence: e.basisConf, EvidenceCount: e.evid, WeightCause: e.cause})
		}
	}
	return assembleAttackPath(pathNodes, steps)
}

// KShortestPaths returns up to k highest-probability loopless paths from src to
// dst (node IDs), best first.
//
// Yen's algorithm is O(k · n · (m + n log n)): k is a multiplier on real work, and it
// comes straight from the caller. Cancellation is the backstop that keeps a hostile k
// from outliving the request that asked for it - the api layer bounds k itself.
func KShortestPaths(ctx context.Context, snap graph.Snapshot, src, dst string, k int) ([]AttackPath, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g := newWGraph(snap)
	cands := g.kShortest(src, dst, k)
	out := make([]AttackPath, 0, len(cands))
	for _, c := range cands {
		out = append(out, g.toAttackPath(c.nodes))
	}
	return out, nil
}

// KShortestToTarget enumerates the top-k routes to dst from every seed - the same seeds
// the path list and the risk simulation start from (ontology.Node.IsSeed) - or from
// `from` when non-empty, merged and ranked best-first.
func KShortestToTarget(ctx context.Context, snap graph.Snapshot, from, dst string, k int) ([]AttackPath, error) {
	var seeds []string
	if from != "" {
		seeds = []string{from}
	} else {
		listed := map[string]bool{}
		for _, n := range snap.Nodes {
			if !listed[n.ID] && n.IsSeed() {
				seeds = append(seeds, n.ID)
			}
			listed[n.ID] = true
		}
	}
	var all []AttackPath
	for _, s := range seeds {
		if s == dst {
			continue
		}
		// One Yen run per seed: the loop multiplies k by the number of seeds,
		// so the check belongs here rather than only at the top.
		found, err := KShortestPaths(ctx, snap, s, dst, k)
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Score > all[j].Score })
	if k > 0 && len(all) > k {
		all = all[:k]
	}
	return all, nil
}

// ── what-if ─────────────────────────────────────────────────────────

// EdgeCut identifies edges to remove. An empty Type matches any edge between
// From and To.
type EdgeCut struct {
	From string
	To   string
	Type ontology.EdgeType
}

// WhatIfResult is the before/after of cutting a set of edges.
type WhatIfResult struct {
	RemovedEdges int            `json:"removed_edges"`
	Before       []AttackPath   `json:"before"`
	After        []AttackPath   `json:"after"`
	BeforeRisk   RiskSimulation `json:"before_risk"`
	AfterRisk    RiskSimulation `json:"after_risk"`
}

// RiskReduction is the drop in P(any crown jewel compromised) the cuts achieve. Both
// runs share their trials, and a cut only takes edges away, so it is never negative.
//
// It saturates: while any one jewel is compromised in every trial - one open to anyone -
// P(any) stays at 1 whatever else is fixed, and this reads 0 for a cut that closed every
// route to another jewel. ExpectedReduction does not.
func (r WhatIfResult) RiskReduction() float64 {
	return r.BeforeRisk.AnyCompromiseProbability - r.AfterRisk.AnyCompromiseProbability
}

// ExpectedReduction is the drop in the expected number of crown jewels compromised: the
// per-jewel reductions added up. It moves for every jewel a cut protects, so it is the
// measure a fix is proven on.
func (r WhatIfResult) ExpectedReduction() float64 {
	return r.BeforeRisk.ExpectedCompromised - r.AfterRisk.ExpectedCompromised
}

// WhatIf recomputes critical paths and quantified risk with the given edges
// removed. Both risk runs use the same `seed`, and so the same trials: every edge that
// survives the cut meets the same fate in each trial as before it (common random
// numbers, see montecarlo.go). The difference between the two runs is therefore the
// cut's own effect - never negative, and exactly zero for an edge no route to a jewel
// crosses - rather than the difference between two independent samples.
// It runs TWO full simulations - before and after - so it costs twice what a plain
// risk simulation does, and an abandoned request must stop both.
func WhatIf(ctx context.Context, snap graph.Snapshot, cuts []EdgeCut, iterations int, seed uint64) (WhatIfResult, error) {
	before, err := SimulateRisk(ctx, snap, iterations, seed)
	if err != nil {
		return WhatIfResult{}, err
	}
	return WhatIfFrom(ctx, snap, before, cuts, iterations, seed)
}

// WhatIfFrom is WhatIf with the uncut simulation already in hand: before must be
// SimulateRisk(ctx, snap, iterations, seed). A caller proving several cuts over one
// graph - every fix in a plan - runs that simulation once instead of once per cut, which
// is half the work: the simulation is nearly all of a what-if's cost (9 s of 18 on a
// 4,000-node graph, against 78 ms for the path searches).
func WhatIfFrom(ctx context.Context, snap graph.Snapshot, before RiskSimulation, cuts []EdgeCut, iterations int, seed uint64) (WhatIfResult, error) {
	return WhatIfFromWith(ctx, snap, before, cuts, iterations, seed, RiskOptions{})
}

// WhatIfFromWith is WhatIfFrom with a choice of what the cut simulation computes. A
// fix's verification reads only the point estimates, so it passes PointOnly - for before
// as well - and skips the credible band and the mixture, most of each simulation's cost.
func WhatIfFromWith(ctx context.Context, snap graph.Snapshot, before RiskSimulation, cuts []EdgeCut, iterations int, seed uint64, opt RiskOptions) (WhatIfResult, error) {
	reduced := cutEdges(snap, cuts)
	after, err := SimulateRiskWith(ctx, reduced, iterations, seed, opt)
	if err != nil {
		return WhatIfResult{}, err
	}
	return WhatIfResult{
		RemovedEdges: len(snap.Edges) - len(reduced.Edges),
		Before:       FindCriticalPaths(snap),
		After:        FindCriticalPaths(reduced),
		BeforeRisk:   before,
		AfterRisk:    after,
	}, nil
}

func cutEdges(snap graph.Snapshot, cuts []EdgeCut) graph.Snapshot {
	matches := func(e ontology.Edge) bool {
		for _, c := range cuts {
			if c.From == e.From && c.To == e.To && (c.Type == "" || c.Type == e.Type) {
				return true
			}
		}
		return false
	}
	edges := make([]ontology.Edge, 0, len(snap.Edges))
	for _, e := range snap.Edges {
		if !matches(e) {
			edges = append(edges, e)
		}
	}
	return graph.Snapshot{Nodes: snap.Nodes, Edges: edges}
}

// ── helpers ─────────────────────────────────────────────────────────

func equalPrefix(path, prefix []string) bool {
	if len(path) < len(prefix) {
		return false
	}
	for i := range prefix {
		if path[i] != prefix[i] {
			return false
		}
	}
	return true
}

func containsPath(set []candPath, c candPath) bool {
	key := pathKey(c.nodes)
	for _, p := range set {
		if pathKey(p.nodes) == key {
			return true
		}
	}
	return false
}

func pathKey(seq []string) string { return strings.Join(seq, ">") }

// shortHash is a tiny stable hash of a path, to disambiguate IDs of multiple
// paths sharing the same endpoints.
func shortHash(s string) string {
	const fnvOffset, fnvPrime = uint32(2166136261), uint32(16777619)
	h := fnvOffset
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= fnvPrime
	}
	return fmt.Sprintf("%08x", h)
}
