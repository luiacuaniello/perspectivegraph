package synthgraph

import (
	"fmt"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The generated shape is what the scale numbers MEAN. If this stopped marking seeds or
// crown jewels, the analyzer would find no paths at all and the benchmark would report a
// flattering figure for work it never did - a scaling claim measured on an empty search.
func TestGeneratedGraphHasSeedsAndJewelsSoPathsCanExist(t *testing.T) {
	const seeds, jewels, layers, width, fanout = 3, 2, 4, 10, 2
	nodes, edges := Build(seeds, jewels, layers, width, fanout, 1)

	if len(nodes) != layers*width {
		t.Fatalf("got %d nodes, want %d", len(nodes), layers*width)
	}
	if len(edges) != (layers-1)*width*fanout {
		t.Fatalf("got %d edges, want %d", len(edges), (layers-1)*width*fanout)
	}

	var gotSeeds, gotJewels int
	for _, n := range nodes {
		if n.Bool(ontology.PropInternetExposed) {
			gotSeeds++
		}
		if n.Bool(ontology.PropCrownJewel) {
			gotJewels++
		}
	}
	if gotSeeds != seeds {
		t.Errorf("%d internet-exposed seeds, want %d - with none, the analyzer searches from nowhere", gotSeeds, seeds)
	}
	if gotJewels != jewels {
		t.Errorf("%d crown jewels, want %d - with none, no path is ever critical", gotJewels, jewels)
	}
}

// Same seed, same graph: a load benchmark whose input changed between runs would compare
// two different workloads and call the difference a regression.
func TestGenerationIsDeterministicForASeed(t *testing.T) {
	// Edges carry maps, so they are compared on the fields that define the shape.
	shape := func(es []ontology.Edge) []string {
		out := make([]string, len(es))
		for i, e := range es {
			out[i] = fmt.Sprintf("%s->%s@%.6f", e.From, e.To, e.ExploitProbability)
		}
		return out
	}
	_, a := Build(2, 2, 3, 6, 2, 42)
	_, b := Build(2, 2, 3, 6, 2, 42)
	sa, sb := shape(a), shape(b)
	if len(sa) != len(sb) {
		t.Fatalf("edge counts differ between runs: %d vs %d", len(sa), len(sb))
	}
	for i := range sa {
		if sa[i] != sb[i] {
			t.Fatalf("edge %d differs between two runs with the same seed: %s vs %s", i, sa[i], sb[i])
		}
	}

	_, c := Build(2, 2, 3, 6, 2, 43)
	if sc := shape(c); len(sc) == len(sa) {
		same := true
		for i := range sa {
			if sa[i] != sc[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("a different seed produced an identical graph, so the seed does nothing")
		}
	}
}

// Every edge must carry a usable probability: a zero would make the path score zero and
// the route would never rank, so the generated surface would be unreachable by
// construction.
func TestEveryEdgeCarriesAUsableProbability(t *testing.T) {
	_, edges := Build(2, 2, 4, 8, 3, 7)
	for i, e := range edges {
		if e.ExploitProbability <= 0 || e.ExploitProbability > 1 {
			t.Fatalf("edge %d has probability %v, outside (0,1]", i, e.ExploitProbability)
		}
		if e.From == "" || e.To == "" {
			t.Fatalf("edge %d has an empty endpoint", i)
		}
	}
}
