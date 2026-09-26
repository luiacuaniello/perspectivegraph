package graph_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// assertSweepContract holds both stores to the rule a sweep follows: a source retracts
// what it no longer lists in a scope it described in full, and an element leaves the
// graph only when nobody asserts it any more. It deletes data, so every way it could
// delete too much is asserted here, on both backends.
func assertSweepContract(t *testing.T, s graph.Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error, what string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	sweeper, ok := s.(graph.Sweeper)
	if !ok {
		t.Fatal("store does not implement graph.Sweeper")
	}
	epocher, ok := s.(graph.RemovalEpocher)
	if !ok {
		t.Fatal("store does not implement graph.RemovalEpocher")
	}
	t0, t1, t2 := time.Now().Add(-10*time.Minute), time.Now().Add(-5*time.Minute), time.Now()
	node := func(id string, l ontology.Label) ontology.Node { return ontology.Node{ID: id, Label: l, Name: id} }
	edge := func(ty ontology.EdgeType, from, to string) ontology.Edge {
		return ontology.Edge{Type: ty, From: from, To: to, ExploitProbability: 0.5}
	}
	scan := func(scope string, taken time.Time, nodes []ontology.Node, edges []ontology.Edge) {
		t.Helper()
		must(graph.ApplyEvent(ctx, s, ontology.Event{Source: "trivy", ObservedAt: taken,
			Snapshot: &ontology.Snapshot{Scope: scope, Taken: taken}, Nodes: nodes, Edges: edges}), "snapshot "+scope)
	}
	partial := func(source string, nodes []ontology.Node, edges []ontology.Edge) {
		t.Helper()
		must(graph.ApplyEvent(ctx, s, ontology.Event{Source: source, ObservedAt: t0, Nodes: nodes, Edges: edges}), source)
	}

	// The image's scan: a library that will be upgraded, its CVE, and a library it shares
	// with another image.
	scan("image:sw-app", t0,
		[]ontology.Node{node("sw-img", ontology.LabelImage), node("sw-lib-old", ontology.LabelLibrary),
			node("sw-cve", ontology.LabelCVE), node("sw-lib-shared", ontology.LabelLibrary)},
		[]ontology.Edge{edge(ontology.EdgeDependsOn, "sw-img", "sw-lib-old"), edge(ontology.EdgeAffects, "sw-lib-old", "sw-cve"),
			edge(ontology.EdgeDependsOn, "sw-img", "sw-lib-shared")})
	// Another image's scan, which lists the shared library too.
	scan("image:sw-other", t0,
		[]ontology.Node{node("sw-other", ontology.LabelImage), node("sw-lib-shared", ontology.LabelLibrary)},
		[]ontology.Edge{edge(ontology.EdgeDependsOn, "sw-other", "sw-lib-shared")})
	// Partial feeds: a workload that runs the image, and an estate edge from the CVE to a
	// secret it exposes.
	partial("k8s", []ontology.Node{node("sw-pod", ontology.LabelContainer), node("sw-img", ontology.LabelImage)},
		[]ontology.Edge{edge(ontology.EdgeHosts, "sw-pod", "sw-img")})
	partial("cloudnet", []ontology.Node{node("sw-secret", ontology.LabelSecret)},
		[]ontology.Edge{edge(ontology.EdgeExploits, "sw-cve", "sw-secret")})
	// And a node nobody recorded an origin for.
	must(s.UpsertNode(ctx, node("sw-untracked", ontology.LabelContainer)), "untracked node")
	must(s.UpsertEdge(ctx, edge(ontology.EdgeConnectsTo, "sw-untracked", "sw-img")), "untracked edge")

	before, err := epocher.RemovalEpoch(ctx)
	must(err, "removal epoch")

	// The image is rescanned with the library upgraded.
	scan("image:sw-app", t1,
		[]ontology.Node{node("sw-img", ontology.LabelImage), node("sw-lib-new", ontology.LabelLibrary),
			node("sw-lib-shared", ontology.LabelLibrary)},
		[]ontology.Edge{edge(ontology.EdgeDependsOn, "sw-img", "sw-lib-new"), edge(ontology.EdgeDependsOn, "sw-img", "sw-lib-shared")})

	// An OLDER snapshot of the same scope landing late retracts nothing the newer one said.
	stats, err := sweeper.Sweep(ctx, "trivy", "image:sw-app", t0)
	must(err, "late sweep")
	if stats.Removed() {
		t.Fatalf("a sweep as of an older snapshot removed %+v", stats)
	}

	stats, err = sweeper.Sweep(ctx, "trivy", "image:sw-app", t1)
	must(err, "sweep")
	snap, err := s.Snapshot(ctx)
	must(err, "snapshot after sweep")
	nodes := snap.NodeByID()
	edges := map[string]bool{}
	for _, e := range snap.Edges {
		edges[string(e.Type)+" "+e.From+"->"+e.To] = true
	}
	for _, id := range []string{"sw-lib-old", "sw-cve"} {
		if _, ok := nodes[id]; ok {
			t.Errorf("%s: only the old scan listed it, and it is still in the graph", id)
		}
	}
	for _, id := range []string{"sw-img", "sw-lib-shared", "sw-lib-new", "sw-pod", "sw-secret", "sw-untracked", "sw-other"} {
		if _, ok := nodes[id]; !ok {
			t.Errorf("%s: something still asserts it (or nobody recorded who did), and the sweep removed it", id)
		}
	}
	for _, k := range []string{"DEPENDS_ON sw-img->sw-lib-old", "AFFECTS sw-lib-old->sw-cve", "EXPLOITS sw-cve->sw-secret"} {
		if edges[k] {
			t.Errorf("%s is still in the graph", k)
		}
	}
	for _, k := range []string{"DEPENDS_ON sw-img->sw-lib-new", "DEPENDS_ON sw-img->sw-lib-shared",
		"DEPENDS_ON sw-other->sw-lib-shared", "HOSTS sw-pod->sw-img", "CONNECTS_TO sw-untracked->sw-img"} {
		if !edges[k] {
			t.Errorf("%s was removed", k)
		}
	}
	if stats.Nodes != 2 || stats.Parked != 1 {
		t.Errorf("stats = %+v, want 2 nodes removed and the estate's edge parked", stats)
	}
	if after, err := epocher.RemovalEpoch(ctx); err != nil || after == before {
		t.Errorf("removal epoch %d -> %d (%v): a consumer patching from deltas would never see the removal", before, after, err)
	}

	// The estate's edge was not the scan's to retract: it waits for its CVE, and lands
	// again when a scan lists the CVE once more.
	if p, ok := graph.AsEdgeParker(s); ok {
		waiting, _, err := p.PendingEdges(ctx, -1)
		must(err, "pending edges")
		found := false
		for _, e := range waiting {
			found = found || (e.From == "sw-cve" && e.To == "sw-secret")
		}
		if !found {
			t.Errorf("the estate's edge from the removed CVE is neither in the graph nor waiting: %v", waiting)
		}
	}
	scan("image:sw-app", t2,
		[]ontology.Node{node("sw-img", ontology.LabelImage), node("sw-lib-old", ontology.LabelLibrary), node("sw-cve", ontology.LabelCVE)},
		[]ontology.Edge{edge(ontology.EdgeDependsOn, "sw-img", "sw-lib-old"), edge(ontology.EdgeAffects, "sw-lib-old", "sw-cve")})
	snap, err = s.Snapshot(ctx)
	must(err, "snapshot after the CVE came back")
	back := false
	for _, e := range snap.Edges {
		back = back || (e.From == "sw-cve" && e.To == "sw-secret")
	}
	if !back {
		t.Error("the estate's edge did not land again when its CVE came back")
	}

	// The empty scope is the partial observations': nothing retracts them by omission.
	if _, err := sweeper.Sweep(ctx, "k8s", "", t2.Add(time.Hour)); !errors.Is(err, graph.ErrEmptyScope) {
		t.Errorf("sweep of the empty scope: %v, want ErrEmptyScope", err)
	}
}

// An element already in a graph when provenance begins - every element of an upgraded
// install - was asserted by someone nobody recorded. It is given an origin no sweep
// retracts, so the first complete snapshot to mention it cannot take it away from a feed
// that has not been back since the upgrade. It must run on a fresh graph, before
// anything records an origin.
func assertElementsBeforeProvenanceAreNeverSwept(t *testing.T, s graph.Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertNode(ctx, ontology.Node{ID: "pre-prov", Label: ontology.LabelContainer, Name: "pre-prov"}); err != nil {
		t.Fatal(err)
	}
	taken := time.Now().Add(-time.Minute)
	for _, id := range []string{"pre-prov", "post-prov"} {
		if err := graph.ApplyEvent(ctx, s, ontology.Event{Source: "k8s", ObservedAt: taken,
			Snapshot: &ontology.Snapshot{Scope: "cluster:pre", Taken: taken},
			Nodes:    []ontology.Node{{ID: id, Label: ontology.LabelContainer, Name: id}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.(graph.Sweeper).Sweep(ctx, "k8s", "cluster:pre", time.Now()); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nodes := snap.NodeByID()
	if _, ok := nodes["pre-prov"]; !ok {
		t.Error("a node from before provenance was swept")
	}
	if _, ok := nodes["post-prov"]; ok {
		t.Error("a node only the snapshot asserted survived its sweep")
	}
}
