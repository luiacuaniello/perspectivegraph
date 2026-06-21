// Package normalization consumes events off the bus, resolves asset identity
// across tools (so Trivy's "image:tag", an ECR image URI, and a K8s PodSpec
// collapse to one node), and upserts the result into the graph.
//
// Identity resolution here is two complementary things:
//
//   - Canonicalization — rewriting ids so the same real asset reported by
//     different tools converges (registry prefixes stripped from image refs,
//     plus a learned alias table).
//   - Relationship inference — synthesizing edges that no single tool reports
//     but the graph needs, e.g. linking a runtime/cloud Container to the Image
//     a scanner analyzed (Container --HOSTS--> Image) via its image reference.
package normalization

import (
	"context"
	"log/slog"
	"strings"

	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/internal/search"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

// Normalizer is the bus handler that turns events into graph mutations.
type Normalizer struct {
	store   graph.Store
	indexer search.Indexer
	aliases map[string]string // alternate id -> canonical id
}

func New(store graph.Store) *Normalizer {
	return &Normalizer{store: store, indexer: search.Noop{}, aliases: map[string]string{}}
}

// WithIndexer attaches a full-text indexer; resolved nodes are indexed after
// they are written to the graph. Returns the normalizer for chaining.
func (n *Normalizer) WithIndexer(idx search.Indexer) *Normalizer {
	if idx != nil {
		n.indexer = idx
	}
	return n
}

// Alias records that two collector-specific ids refer to the same asset.
func (n *Normalizer) Alias(altID, canonicalID string) {
	n.aliases[altID] = canonicalID
}

// Handle is the broker consumer callback.
func (n *Normalizer) Handle(ctx context.Context, ev ontology.Event) error {
	ev = n.canonicalize(ev)
	ev = inferImageHosts(ev)
	if err := graph.ApplyEvent(ctx, n.store, ev); err != nil {
		return err
	}
	if n.indexer.Enabled() {
		if err := n.indexer.Index(ctx, ev.Nodes); err != nil {
			slog.Warn("full-text index failed (continuing)", "err", err)
		}
	}
	return nil
}

// canonicalize rewrites node/edge ids through (a) image-ref normalization and
// (b) the learned alias table, so duplicate assets converge before they hit the
// graph.
func (n *Normalizer) canonicalize(ev ontology.Event) ontology.Event {
	rewrite := map[string]string{}
	for i := range ev.Nodes {
		node := &ev.Nodes[i]
		canon := node.ID
		// Images: key on the registry-stripped repo:tag.
		if node.Label == ontology.LabelImage {
			if id := ontology.NewID(ontology.LabelImage, NormalizeImageRef(node.Name)); id != canon {
				canon = id
			}
		}
		if alias, ok := n.aliases[canon]; ok {
			canon = alias
		}
		if canon != node.ID {
			rewrite[node.ID] = canon
			node.ID = canon
		}
	}
	if len(rewrite) > 0 || len(n.aliases) > 0 {
		apply := func(id string) string {
			if c, ok := rewrite[id]; ok {
				return c
			}
			if c, ok := n.aliases[id]; ok {
				return c
			}
			return id
		}
		for i := range ev.Edges {
			ev.Edges[i].From = apply(ev.Edges[i].From)
			ev.Edges[i].To = apply(ev.Edges[i].To)
		}
	}
	return ev
}

// inferImageHosts links any Container/VM that declares the image it runs to the
// corresponding Image node, so a finding on the image becomes reachable from
// the workload. The Image node is stubbed in case no scanner reported it yet.
func inferImageHosts(ev ontology.Event) ontology.Event {
	for _, node := range ev.Nodes {
		if node.Label != ontology.LabelContainer && node.Label != ontology.LabelVirtualMachine {
			continue
		}
		ref, _ := node.Properties[ontology.PropImageRef].(string)
		if ref == "" {
			continue
		}
		imgID := ontology.NewID(ontology.LabelImage, NormalizeImageRef(ref))
		if !hasNode(ev.Nodes, imgID) {
			ev.Nodes = append(ev.Nodes, ontology.Node{
				ID:    imgID,
				Label: ontology.LabelImage,
				Name:  NormalizeImageRef(ref),
			})
		}
		if !hasEdge(ev.Edges, ontology.EdgeHosts, node.ID, imgID) {
			ev.Edges = append(ev.Edges, ontology.Edge{
				Type:               ontology.EdgeHosts,
				From:               node.ID,
				To:                 imgID,
				ExploitProbability: 0.95,
			})
		}
	}
	return ev
}

// NormalizeImageRef strips a registry host prefix so equivalent image references
// resolve to the same node:
//
//	123.dkr.ecr.us-east-1.amazonaws.com/payments-api:1.4.2  ->  payments-api:1.4.2
//	docker.io/library/nginx:1.25                            ->  library/nginx:1.25
//	payments-api:1.4.2                                      ->  payments-api:1.4.2 (unchanged)
func NormalizeImageRef(ref string) string {
	ref = strings.TrimSpace(ref)
	host, rest, ok := strings.Cut(ref, "/")
	if ok && (strings.Contains(host, ".") || strings.Contains(host, ":")) {
		return rest
	}
	return ref
}

func hasNode(nodes []ontology.Node, id string) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

func hasEdge(edges []ontology.Edge, t ontology.EdgeType, from, to string) bool {
	for _, e := range edges {
		if e.Type == t && e.From == from && e.To == to {
			return true
		}
	}
	return false
}
