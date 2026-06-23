package analyzer

import (
	"testing"
)

// TestParallelMatchesSequential is the safety contract for the worker pool: the
// per-seed Dijkstra fan-out is a speedup, never a behavior change. The result must
// be byte-for-byte identical (same paths, same scores, same order) no matter how
// many workers ran - so parallelism can be tuned freely without affecting what the
// analyzer reports.
func TestParallelMatchesSequential(t *testing.T) {
	snap := genLayeredGraph(40, 20, 8, 400, 4, 7)
	defer SetPathWorkers(0) // restore auto for other tests

	SetPathWorkers(1)
	seq := FindCriticalPaths(snap)
	if len(seq) == 0 {
		t.Fatal("expected some critical paths in the synthetic graph")
	}

	for _, w := range []int{2, 4, 8, 16} {
		SetPathWorkers(w)
		got := FindCriticalPaths(snap)
		if len(got) != len(seq) {
			t.Fatalf("workers=%d: got %d paths, sequential had %d", w, len(got), len(seq))
		}
		for i := range seq {
			a, b := seq[i], got[i]
			if a.ID != b.ID || a.Score != b.Score || a.RuntimeConfirmed != b.RuntimeConfirmed {
				t.Fatalf("workers=%d: path %d differs: seq=(%s,%.6f) par=(%s,%.6f)",
					w, i, a.ID, a.Score, b.ID, b.Score)
			}
			if len(a.Nodes) != len(b.Nodes) {
				t.Fatalf("workers=%d: path %d node count differs: %d vs %d", w, i, len(a.Nodes), len(b.Nodes))
			}
			for j := range a.Nodes {
				if a.Nodes[j].ID != b.Nodes[j].ID {
					t.Fatalf("workers=%d: path %d node %d differs: %s vs %s", w, i, j, a.Nodes[j].ID, b.Nodes[j].ID)
				}
			}
		}
	}
}
