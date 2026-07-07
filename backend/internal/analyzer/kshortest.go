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
// random numbers so the before/after risk delta reflects the cut, not noise.

import (
	"container/heap"
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
		p := e.ExploitProbability
		if p <= 0 {
			p = 0.01
		}
		if p > 1 {
			p = 1
		}
		basis, basisConf, evid := weightBasisOf(e, g.nodes[e.From], g.nodes[e.To])
		oe := outEdge{to: e.To, typ: e.Type, weight: -math.Log(p), prob: p, basis: basis, basisConf: basisConf, evid: evid}
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
		cur := heap.Pop(pq).(heapItem)
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
				heap.Push(pq, heapItem{node: e.to, d: nd})
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

// toAttackPath materializes a node sequence into a scored AttackPath.
func (g *wgraph) toAttackPath(seq []string) AttackPath {
	pathNodes := make([]ontology.Node, 0, len(seq))
	var steps []Step
	score := 1.0
	runtime := false
	for i, id := range seq {
		n := g.nodes[id]
		pathNodes = append(pathNodes, n)
		if n.Bool(ontology.PropRuntimeAlert) {
			runtime = true
		}
		if i+1 < len(seq) {
			e := g.adj[id][seq[i+1]]
			steps = append(steps, Step{EdgeType: e.typ, From: id, To: seq[i+1], Probability: e.prob, WeightBasis: e.basis, WeightConfidence: e.basisConf, EvidenceCount: e.evid})
			score *= e.prob
		}
	}
	conf, label := pathConfidence(steps)
	return AttackPath{
		ID:               fmt.Sprintf("ap-%s-%s-%s", shortID(seq[0]), shortID(seq[len(seq)-1]), shortHash(pathKey(seq))),
		Score:            score,
		Nodes:            pathNodes,
		Steps:            steps,
		RuntimeConfirmed: runtime,
		Confidence:       conf,
		ConfidenceLabel:  label,
	}
}

// KShortestPaths returns up to k highest-probability loopless paths from src to
// dst (node IDs), best first.
func KShortestPaths(snap graph.Snapshot, src, dst string, k int) []AttackPath {
	g := newWGraph(snap)
	cands := g.kShortest(src, dst, k)
	out := make([]AttackPath, 0, len(cands))
	for _, c := range cands {
		out = append(out, g.toAttackPath(c.nodes))
	}
	return out
}

// KShortestToTarget enumerates the top-k routes to dst from every internet seed
// (or from `from` when non-empty), merged and ranked best-first.
func KShortestToTarget(snap graph.Snapshot, from, dst string, k int) []AttackPath {
	var seeds []string
	if from != "" {
		seeds = []string{from}
	} else {
		for _, n := range snap.Nodes {
			if n.Bool(ontology.PropInternetExposed) {
				seeds = append(seeds, n.ID)
			}
		}
	}
	var all []AttackPath
	for _, s := range seeds {
		if s == dst {
			continue
		}
		all = append(all, KShortestPaths(snap, s, dst, k)...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Score > all[j].Score })
	if k > 0 && len(all) > k {
		all = all[:k]
	}
	return all
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

// RiskReduction is the drop in P(any crown jewel compromised) the cuts achieve.
func (r WhatIfResult) RiskReduction() float64 {
	return r.BeforeRisk.AnyCompromiseProbability - r.AfterRisk.AnyCompromiseProbability
}

// WhatIf recomputes critical paths and quantified risk with the given edges
// removed. Both risk runs use the same `seed` for reproducibility; note this is
// NOT a true common-random-numbers variance reduction (the two graphs have
// different edge sets, so the same RNG draws map to different edges) - so make
// the delta meaningful by running enough iterations, not by relying on CRN.
func WhatIf(snap graph.Snapshot, cuts []EdgeCut, iterations int, seed uint64) WhatIfResult {
	reduced := cutEdges(snap, cuts)
	return WhatIfResult{
		RemovedEdges: len(snap.Edges) - len(reduced.Edges),
		Before:       FindCriticalPaths(snap),
		After:        FindCriticalPaths(reduced),
		BeforeRisk:   SimulateRisk(snap, iterations, seed),
		AfterRisk:    SimulateRisk(reduced, iterations, seed),
	}
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
