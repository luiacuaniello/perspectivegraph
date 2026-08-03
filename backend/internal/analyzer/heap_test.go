package analyzer

import (
	"container/heap"
	"math/rand"
	"testing"
)

// refHeap is the container/heap implementation this package used to call directly. It
// exists only here, as the oracle: minHeap must agree with it exactly, not merely
// produce "a" valid heap order.
type refHeap []heapItem

func (h refHeap) Len() int           { return len(h) }
func (h refHeap) Less(i, j int) bool { return h[i].d < h[j].d }
func (h refHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *refHeap) Push(x any)        { *h = append(*h, x.(heapItem)) }
func (h *refHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// The hand-rolled heap replaced container/heap to stop boxing a 24-byte heapItem on
// every push and pop. Dropping the interface is only safe if the ORDER is unchanged:
// dijkstra pops the frontier, so a different choice between two equal-distance entries
// selects a different shortest path, which changes path ids and every artifact generated
// from them. Agreeing on the minimum is not enough - the tie-break has to match too.
func TestMinHeapMatchesContainerHeapExactly(t *testing.T) {
	rng := rand.New(rand.NewSource(7))

	for trial := 0; trial < 300; trial++ {
		var mine minHeap
		var ref refHeap

		// Distances are drawn from a deliberately tiny set so ties are frequent -
		// that is the case the whole test exists for. Real edge probabilities repeat
		// for the same reason (shared severity defaults produce identical weights).
		ops := 1 + rng.Intn(200)
		for i := 0; i < ops; i++ {
			if len(mine) > 0 && rng.Intn(3) == 0 {
				got := mine.pop()
				want := heap.Pop(&ref).(heapItem)
				if got != want {
					t.Fatalf("trial %d op %d: pop = %+v, container/heap = %+v", trial, i, got, want)
				}
				continue
			}
			it := heapItem{
				node: string(rune('a' + rng.Intn(6))),
				d:    float64(rng.Intn(5)), // few distinct values ⇒ many ties
			}
			mine.push(it)
			heap.Push(&ref, it)
		}

		// Drain: the orders must coincide all the way down, not just at the top.
		for len(mine) > 0 {
			got := mine.pop()
			want := heap.Pop(&ref).(heapItem)
			if got != want {
				t.Fatalf("trial %d drain: pop = %+v, container/heap = %+v", trial, got, want)
			}
		}
		if len(ref) != 0 {
			t.Fatalf("trial %d: reference heap has %d left after ours drained", trial, len(ref))
		}
	}
}

// Whatever the tie-break, the sequence of popped distances must still be non-decreasing:
// the property dijkstra's correctness actually rests on.
func TestMinHeapPopsInNonDecreasingOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	var h minHeap
	for i := 0; i < 5000; i++ {
		h.push(heapItem{node: "n", d: rng.Float64() * 100})
	}
	last := -1.0
	for h.Len() > 0 {
		d := h.pop().d
		if d < last {
			t.Fatalf("popped %v after %v - heap order violated", d, last)
		}
		last = d
	}
}

// A single-element heap is the boundary the sift-down loop has to survive: pop swaps
// index 0 with itself and then sifts over zero remaining elements.
func TestMinHeapSingleElement(t *testing.T) {
	var h minHeap
	h.push(heapItem{node: "only", d: 3})
	if got := h.pop(); got.node != "only" || got.d != 3 {
		t.Fatalf("pop = %+v", got)
	}
	if h.Len() != 0 {
		t.Fatalf("len = %d after draining", h.Len())
	}
}

// push must not allocate: the whole point of dropping container/heap was that boxing a
// heapItem into `any` cost one allocation per call, 86% of this package's total.
func TestMinHeapPushDoesNotAllocate(t *testing.T) {
	h := make(minHeap, 0, 1024)
	got := testing.AllocsPerRun(200, func() {
		h = h[:0]
		for i := 0; i < 512; i++ {
			h.push(heapItem{node: "n", d: float64(512 - i)})
		}
		for h.Len() > 0 {
			_ = h.pop()
		}
	})
	if got != 0 {
		t.Errorf("%.1f allocations per push/pop cycle, want 0 - the interface boxing is back", got)
	}
}
