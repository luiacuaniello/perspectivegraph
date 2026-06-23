// Package policy evaluates architectural invariants over the graph - the
// "policy as a graph" idea. An invariant is a forbidden shape: either a node
// that must not exist (e.g. a public data store) or a path that must not
// connect two kinds of node (e.g. anything internet-exposed reaching a crown
// jewel). The engine reports each match as a Violation, which the pipeline can
// surface to architects or fail a CI gate on.
package policy

import (
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// NodeMatch is a predicate over a graph node.
type NodeMatch func(ontology.Node) bool

// Invariant is a forbidden graph shape.
//
//   - Path invariant (Source != nil): no path may run from a Source node to a
//     Target node (optionally restricted to the edge types in Via).
//   - Node invariant (Source == nil): no node may match Target.
type Invariant struct {
	ID          string
	Description string
	Severity    string // CRITICAL | HIGH | MEDIUM | LOW
	Source      NodeMatch
	Target      NodeMatch
	Via         map[ontology.EdgeType]bool // nil = any edge type
}

// Violation is a concrete breach of an invariant, with the offending node(s).
type Violation struct {
	InvariantID string          `json:"invariant_id"`
	Description string          `json:"description"`
	Severity    string          `json:"severity"`
	Nodes       []ontology.Node `json:"nodes"` // the offending path (or single node)
}

// Engine evaluates a set of invariants against graph snapshots.
type Engine struct {
	invariants []Invariant
}

func NewEngine(inv ...Invariant) *Engine { return &Engine{invariants: inv} }

// Evaluate returns every violation found in the snapshot.
func (e *Engine) Evaluate(snap graph.Snapshot) []Violation {
	index := snap.NodeByID()
	adj := buildAdjacency(snap.Edges)

	var out []Violation
	for _, inv := range e.invariants {
		if inv.Source == nil {
			out = append(out, e.evalNode(inv, snap)...)
		} else {
			out = append(out, e.evalPath(inv, snap, index, adj)...)
		}
	}
	return out
}

func (e *Engine) evalNode(inv Invariant, snap graph.Snapshot) []Violation {
	var out []Violation
	for _, n := range snap.Nodes {
		if inv.Target(n) {
			out = append(out, Violation{
				InvariantID: inv.ID, Description: inv.Description, Severity: inv.Severity,
				Nodes: []ontology.Node{n},
			})
		}
	}
	return out
}

func (e *Engine) evalPath(inv Invariant, snap graph.Snapshot, index map[string]ontology.Node, adj map[string][]edge) []Violation {
	var out []Violation
	for _, src := range snap.Nodes {
		if !inv.Source(src) {
			continue
		}
		if path := bfs(src.ID, inv, index, adj); path != nil {
			nodes := make([]ontology.Node, len(path))
			for i, id := range path {
				nodes[i] = index[id]
			}
			out = append(out, Violation{
				InvariantID: inv.ID, Description: inv.Description, Severity: inv.Severity,
				Nodes: nodes,
			})
		}
	}
	return out
}

type edge struct {
	to  string
	typ ontology.EdgeType
}

func buildAdjacency(edges []ontology.Edge) map[string][]edge {
	adj := make(map[string][]edge)
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], edge{to: e.To, typ: e.Type})
	}
	return adj
}

// bfs finds a shortest path from src to any Target node, honoring Via edge
// restrictions, and returns the node-id sequence (nil if none).
func bfs(src string, inv Invariant, index map[string]ontology.Node, adj map[string][]edge) []string {
	visited := map[string]bool{src: true}
	prev := map[string]string{}
	queue := []string{src}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		// A target reached (but not the source itself) is a violation.
		if cur != src {
			if n, ok := index[cur]; ok && inv.Target(n) {
				return reconstruct(prev, src, cur)
			}
		}
		for _, e := range adj[cur] {
			if inv.Via != nil && !inv.Via[e.typ] {
				continue
			}
			if visited[e.to] {
				continue
			}
			visited[e.to] = true
			prev[e.to] = cur
			queue = append(queue, e.to)
		}
	}
	return nil
}

func reconstruct(prev map[string]string, src, dst string) []string {
	var rev []string
	for at := dst; at != src; at = prev[at] {
		rev = append(rev, at)
	}
	rev = append(rev, src)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}
