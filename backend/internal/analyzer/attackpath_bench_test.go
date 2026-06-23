package analyzer

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// genLayeredGraph builds a deterministic, scale-test attack surface: `layers`
// ranks of `width` nodes, every node wired forward to `fanout` nodes in the next
// rank with a pseudo-random exploit probability. The first `seeds` nodes of rank 0
// are internet-exposed; the last `jewels` nodes of the final rank are crown jewels.
// It is the synthetic load the pathfinding benchmarks scale up - large but bounded
// (a DAG), so a result is reproducible from `seed` and independent of wall clock.
func genLayeredGraph(seeds, jewels, layers, width, fanout int, seed int64) graph.Snapshot {
	rng := rand.New(rand.NewSource(seed))
	var snap graph.Snapshot

	id := func(layer, i int) string { return fmt.Sprintf("n-%d-%d", layer, i) }

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
			snap.Nodes = append(snap.Nodes, n)
		}
	}

	for l := 0; l < layers-1; l++ {
		for i := 0; i < width; i++ {
			for f := 0; f < fanout; f++ {
				to := rng.Intn(width)
				p := 0.2 + rng.Float64()*0.8 // (0.2, 1.0]
				snap.Edges = append(snap.Edges, ontology.Edge{
					Type:               ontology.EdgeConnectsTo,
					From:               id(l, i),
					To:                 id(l+1, to),
					ExploitProbability: p,
					Properties:         map[string]any{},
				})
			}
		}
	}
	return snap
}

// BenchmarkFindCriticalPaths measures the per-pass pathfinding cost as the graph
// and the number of entry points grow - the dimension that stresses the analyzer.
// Run: go test ./internal/analyzer -bench BenchmarkFindCriticalPaths -benchmem
func BenchmarkFindCriticalPaths(b *testing.B) {
	cases := []struct {
		name                              string
		seeds, jewels, layers, width, fan int
	}{
		{"small_8seeds", 8, 8, 6, 200, 4},
		{"medium_32seeds", 32, 16, 8, 500, 4},
		{"large_64seeds", 64, 32, 10, 1000, 5},
	}
	for _, c := range cases {
		snap := genLayeredGraph(c.seeds, c.jewels, c.layers, c.width, c.fan, 42)
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = FindCriticalPaths(snap)
			}
		})
	}
}

// BenchmarkPathfindWorkers isolates the parallelism speedup: the same graph, the
// same result, run with a growing worker count. Run:
// go test ./internal/analyzer -bench BenchmarkPathfindWorkers
func BenchmarkPathfindWorkers(b *testing.B) {
	snap := genLayeredGraph(64, 32, 10, 1000, 5, 42)
	defer SetPathWorkers(0) // restore auto for any later test
	for _, w := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("workers_%d", w), func(b *testing.B) {
			SetPathWorkers(w)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = FindCriticalPaths(snap)
			}
		})
	}
}
