// Package synthgraph generates a synthetic layered attack surface, for load and scale
// testing of the analyzer.
//
// It is a package rather than a helper inside the load-generator subcommand because the
// SHAPE it produces is what the scaling numbers mean. If it silently stopped marking
// seeds, or wired every layer to the same node, the analyzer would find no paths and the
// benchmark would report a flattering figure for work it never did.
package synthgraph

import (
	"fmt"
	"math/rand"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Build builds the synthetic layered attack surface as node and edge slices.
// ObservedAt on the carrying events is now, so the ingest layer stamps every
// element's last_seen - which keeps the incremental (delta) snapshot path working
// for genload-sourced data too.
func Build(seeds, jewels, layers, width, fanout int, randSeed int64) ([]ontology.Node, []ontology.Edge) {
	rng := rand.New(rand.NewSource(randSeed)) // #nosec G404 -- deterministic PRNG for synthetic-graph generation, not security-sensitive
	id := func(layer, i int) string { return fmt.Sprintf("genload-%d-%d", layer, i) }

	var nodes []ontology.Node
	for l := 0; l < layers; l++ {
		for i := 0; i < width; i++ {
			n := ontology.Node{
				ID:         id(l, i),
				Label:      ontology.LabelContainer,
				Name:       id(l, i),
				Properties: map[string]any{},
			}
			if l == 0 && i < seeds {
				n.Properties[ontology.PropInternetExposed] = true
			}
			if l == layers-1 && i >= width-jewels {
				n.Properties[ontology.PropCrownJewel] = true
			}
			nodes = append(nodes, n)
		}
	}

	var edges []ontology.Edge
	for l := 0; l < layers-1; l++ {
		for i := 0; i < width; i++ {
			for f := 0; f < fanout; f++ {
				edges = append(edges, ontology.Edge{
					Type:               ontology.EdgeConnectsTo,
					From:               id(l, i),
					To:                 id(l+1, rng.Intn(width)),
					ExploitProbability: 0.2 + rng.Float64()*0.8,
				})
			}
		}
	}
	return nodes, edges
}
