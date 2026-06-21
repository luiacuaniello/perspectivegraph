// Package analyzer turns the graph into ranked attack paths.
//
// An attack path P is a sequence of nodes v₁ → … → vₖ from an internet-exposed
// seed to a crown-jewel target. Each edge carries an exploit probability
// p ∈ (0,1]; the path score is the product S(P) = ∏ p. We convert each edge to
// a cost w = -ln(p) so that maximizing S(P) becomes a shortest-path problem
// (minimizing Σ w), which we solve with Dijkstra from every seed.
package analyzer

import (
	"container/heap"
	"fmt"
	"math"
	"sort"

	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

// Step is one hop along an attack path.
type Step struct {
	EdgeType    ontology.EdgeType `json:"edge_type"`
	From        string            `json:"from"`
	To          string            `json:"to"`
	Probability float64           `json:"probability"`
}

// AttackPath is a scored route from an exposed seed to a crown jewel.
type AttackPath struct {
	ID    string          `json:"id"`
	Score float64         `json:"score"` // S(P) = ∏ p, in (0,1]
	Nodes []ontology.Node `json:"nodes"`
	Steps []Step          `json:"steps"`
	// RuntimeConfirmed is true when some node on the path carries a live Falco
	// runtime alert — the path isn't just reachable, it's being exercised.
	RuntimeConfirmed bool `json:"runtime_confirmed"`
}

// Seed and target node of the path, for convenience.
func (p AttackPath) Source() ontology.Node { return p.Nodes[0] }
func (p AttackPath) Target() ontology.Node { return p.Nodes[len(p.Nodes)-1] }

// FindCriticalPaths returns, for every (seed, crown-jewel) pair that is
// reachable, the single highest-probability path, sorted by score descending.
func FindCriticalPaths(snap graph.Snapshot) []AttackPath {
	nodes := snap.NodeByID()
	adj := buildAdjacency(snap.Edges)

	var seeds, jewels []string
	for _, n := range snap.Nodes {
		if n.Bool(ontology.PropInternetExposed) {
			seeds = append(seeds, n.ID)
		}
		if n.Bool(ontology.PropCrownJewel) {
			jewels = append(jewels, n.ID)
		}
	}

	var paths []AttackPath
	for _, seed := range seeds {
		dist, prev := dijkstra(seed, adj)
		for _, jewel := range jewels {
			if seed == jewel {
				continue
			}
			d, ok := dist[jewel]
			if !ok || math.IsInf(d, 1) {
				continue // unreachable
			}
			paths = append(paths, reconstruct(seed, jewel, prev, adj, nodes))
		}
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

// ── Dijkstra ────────────────────────────────────────────────────────

type outEdge struct {
	to     string
	typ    ontology.EdgeType
	weight float64 // -ln(p)
	prob   float64
}

func buildAdjacency(edges []ontology.Edge) map[string][]outEdge {
	adj := make(map[string][]outEdge)
	for _, e := range edges {
		p := e.ExploitProbability
		if p <= 0 {
			p = 0.01 // unknown edges remain traversable but costly
		}
		if p > 1 {
			p = 1
		}
		adj[e.From] = append(adj[e.From], outEdge{
			to:     e.To,
			typ:    e.Type,
			weight: -math.Log(p),
			prob:   p,
		})
	}
	return adj
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
				prev[e.to] = Step{EdgeType: e.typ, From: cur.node, To: e.to, Probability: e.prob}
				heap.Push(pq, heapItem{node: e.to, d: nd})
			}
		}
	}
	return dist, prev
}

func reconstruct(seed, jewel string, prev map[string]Step, adj map[string][]outEdge, nodes map[string]ontology.Node) AttackPath {
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

	pathNodes := []ontology.Node{nodes[seed]}
	score := 1.0
	runtimeConfirmed := nodes[seed].Bool(ontology.PropRuntimeAlert)
	for _, st := range steps {
		n := nodes[st.To]
		pathNodes = append(pathNodes, n)
		score *= st.Probability
		if n.Bool(ontology.PropRuntimeAlert) {
			runtimeConfirmed = true
		}
	}

	return AttackPath{
		ID:               fmt.Sprintf("ap-%s-%s", shortID(seed), shortID(jewel)),
		Score:            score,
		Nodes:            pathNodes,
		Steps:            steps,
		RuntimeConfirmed: runtimeConfirmed,
	}
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
