// Store-contract suite: every graph.Store implementation must accumulate node
// properties across upserts, keep the stored name when an update carries none,
// and round-trip edges through Snapshot. The same assertions run against the
// in-memory store (always) and Apache AGE (when Postgres is reachable), so the
// two backends cannot silently diverge again.
package graph_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/age"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestMemoryStoreContract(t *testing.T) {
	runStoreContract(t, memory.New())
}

func TestAGEStoreContract(t *testing.T) {
	dsn := os.Getenv("PERSPECTIVE_TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "host=localhost port=5432 user=perspective password=perspective dbname=perspectivegraph sslmode=disable"
	}
	const testGraph = "perspective_contract_test"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("postgres not available: %v", err)
	}

	// AGE's catalog functions are session-scoped: keep one connection for setup.
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Skipf("postgres connection: %v", err)
	}
	defer conn.Close()
	setup := []string{
		`CREATE EXTENSION IF NOT EXISTS age`, // self-sufficient: works on a bare Postgres+AGE image
		`LOAD 'age'`,
		`SET search_path = ag_catalog, "$user", public`,
		fmt.Sprintf(`SELECT create_graph('%s')
		 WHERE NOT EXISTS (SELECT 1 FROM ag_catalog.ag_graph WHERE name = '%s')`, testGraph, testGraph),
	}
	for _, q := range setup {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			t.Skipf("AGE not available (%s): %v", q, err)
		}
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			fmt.Sprintf(`SELECT drop_graph('%s', true)`, testGraph))
	})

	store, err := age.Open(ctx, dsn, testGraph)
	if err != nil {
		t.Fatalf("open AGE store: %v", err)
	}
	defer store.Close()

	runStoreContract(t, store)
	assertPathfinderEquivalence(t, store)
}

// assertPathfinderEquivalence proves the DB-side Cypher path finder agrees with
// the in-process Dijkstra: seeded with two routes of different probability, both
// must return the same single best path with the same score.
func assertPathfinderEquivalence(t *testing.T, store graph.Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// pf-lb(internet) -0.9-> pf-c -0.5-> pf-v -0.8-> pf-j(jewel)   S = 0.36
	//                  pf-c -0.2--------------------> pf-j          S = 0.18 (weaker)
	for _, n := range []ontology.Node{
		{ID: "pf-lb", Label: ontology.LabelLoadBalancer, Name: "pf-edge", Properties: map[string]any{ontology.PropInternetExposed: true}},
		{ID: "pf-c", Label: ontology.LabelContainer, Name: "pf-c"},
		{ID: "pf-v", Label: ontology.LabelCVE, Name: "pf-cve"},
		{ID: "pf-j", Label: ontology.LabelIAMRole, Name: "pf-admin", Properties: map[string]any{ontology.PropCrownJewel: true}},
	} {
		must(store.UpsertNode(ctx, n))
	}
	for _, e := range []ontology.Edge{
		{Type: ontology.EdgeExposes, From: "pf-lb", To: "pf-c", ExploitProbability: 0.9},
		{Type: ontology.EdgeAffects, From: "pf-c", To: "pf-v", ExploitProbability: 0.5},
		{Type: ontology.EdgeExploits, From: "pf-v", To: "pf-j", ExploitProbability: 0.8},
		{Type: ontology.EdgeAssumes, From: "pf-c", To: "pf-j", ExploitProbability: 0.2},
	} {
		must(store.UpsertEdge(ctx, e))
	}

	snap, err := store.Snapshot(ctx)
	must(err)
	dbPaths := analyzer.CriticalPathsVia(ctx, store, snap, 12, true) // force the DB pathfinder
	goPaths := analyzer.FindCriticalPaths(snap)                      // in-process Dijkstra

	score := func(paths []analyzer.AttackPath) map[string]float64 {
		m := map[string]float64{}
		for _, p := range paths {
			m[p.Source().ID+"→"+p.Target().ID] = p.Score
		}
		return m
	}
	db, go_ := score(dbPaths), score(goPaths)
	if len(db) != len(go_) {
		t.Fatalf("path count differs: DB %d vs Dijkstra %d", len(db), len(go_))
	}
	for k, gv := range go_ {
		if dv, ok := db[k]; !ok {
			t.Errorf("DB pathfinder missing path %s found by Dijkstra", k)
		} else if dv < gv-1e-9 || dv > gv+1e-9 {
			t.Errorf("path %s score differs: DB %.4f vs Dijkstra %.4f", k, dv, gv)
		}
	}
	if got := db["pf-lb→pf-j"]; got < 0.36-1e-9 || got > 0.36+1e-9 {
		t.Errorf("best path score = %.4f, want 0.36", got)
	}

	// Recall bound (documented divergence): the best path is 3 hops. With
	// maxHops=2 the DB finder can only reach the weaker 2-hop route (0.18), while
	// the unbounded Dijkstra still finds the 3-hop best (0.36). This is the
	// trade the bound makes — make it explicit so it can't regress silently.
	bounded := analyzer.CriticalPathsVia(ctx, store, snap, 2, true)
	if got := score(bounded)["pf-lb→pf-j"]; got < 0.18-1e-9 || got > 0.18+1e-9 {
		t.Errorf("with maxHops=2 the DB finder should be capped at the 2-hop route (0.18), got %.4f", got)
	}
}

// ApplyEvent must stamp every node and edge with the event's observation time so
// the pruner can later distinguish present from departed assets.
func TestApplyEventStampsLastSeen(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	ev := ontology.Event{
		ObservedAt: time.Unix(1_700_000_000, 0),
		Nodes: []ontology.Node{
			{ID: "n1", Label: ontology.LabelContainer, Name: "a"},
			{ID: "n2", Label: ontology.LabelImage, Name: "b"},
		},
		Edges: []ontology.Edge{{Type: ontology.EdgeHosts, From: "n1", To: "n2", ExploitProbability: 0.9}},
	}
	if err := graph.ApplyEvent(ctx, s, ev); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Snapshot(ctx)
	for _, n := range snap.Nodes {
		if ls, ok := graph.LastSeen(n.Properties); !ok || ls != 1_700_000_000 {
			t.Errorf("node %s last_seen = %d ok=%v, want 1700000000", n.ID, ls, ok)
		}
	}
	for _, e := range snap.Edges {
		if ls, ok := graph.LastSeen(e.Properties); !ok || ls != 1_700_000_000 {
			t.Errorf("edge %s last_seen = %d ok=%v, want 1700000000", e.Type, ls, ok)
		}
	}
}

func runStoreContract(t *testing.T, s graph.Store) {
	t.Helper()
	ctx := context.Background()
	imgID := "Image:contract-test"
	cveID := "CVE:contract-test"

	must := func(err error, what string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	// First observation carries name + PR context (what the Trivy collector stamps).
	must(s.UpsertNode(ctx, ontology.Node{
		ID: imgID, Label: ontology.LabelImage, Name: "payments-api:1.0",
		Properties: map[string]any{"repo_slug": "acme/payments-api", "pr_number": "42"},
	}), "first upsert")
	// A stub re-upsert (no name, no props — what inferImageHosts emits) must not erase anything.
	must(s.UpsertNode(ctx, ontology.Node{ID: imgID, Label: ontology.LabelImage}), "stub upsert")
	// A later observation adds one property and overrides another.
	must(s.UpsertNode(ctx, ontology.Node{
		ID: imgID, Label: ontology.LabelImage,
		Properties: map[string]any{"pr_number": "43", "internet_exposed": true},
	}), "third upsert")

	snap, err := s.Snapshot(ctx)
	must(err, "snapshot")
	node, ok := snap.NodeByID()[imgID]
	if !ok {
		t.Fatalf("node %s missing from snapshot", imgID)
	}
	if node.Name != "payments-api:1.0" {
		t.Errorf("stub upsert erased the name: got %q, want %q", node.Name, "payments-api:1.0")
	}
	if got := fmt.Sprint(node.Properties["repo_slug"]); got != "acme/payments-api" {
		t.Errorf("stub upsert erased repo_slug: got %q", got)
	}
	if got := fmt.Sprint(node.Properties["pr_number"]); got != "43" {
		t.Errorf("later write must win per key: pr_number = %q, want %q", got, "43")
	}
	if got, _ := node.Properties["internet_exposed"].(bool); !got {
		t.Errorf("new property lost: internet_exposed = %v, want true", node.Properties["internet_exposed"])
	}

	// Edges whose endpoints are not in the graph yet must be rejected: the
	// broker redelivers the event until the nodes arrive, so accepting the
	// edge silently (or dropping it) would diverge between implementations.
	if err := s.UpsertEdge(ctx, ontology.Edge{
		Type: ontology.EdgeAffects, From: cveID, To: "Image:not-ingested-yet",
	}); err == nil {
		t.Errorf("edge with missing endpoint accepted; want an error so the broker can redeliver")
	}

	// An edge between existing nodes round-trips with its probability.
	must(s.UpsertNode(ctx, ontology.Node{ID: cveID, Label: ontology.LabelCVE, Name: "CVE-2026-0001"}), "cve upsert")
	must(s.UpsertEdge(ctx, ontology.Edge{
		Type: ontology.EdgeAffects, From: cveID, To: imgID, ExploitProbability: 0.7,
	}), "edge upsert")

	snap, err = s.Snapshot(ctx)
	must(err, "snapshot after edge")
	found := false
	for _, e := range snap.Edges {
		if e.Type == ontology.EdgeAffects && e.From == cveID && e.To == imgID {
			found = true
			if e.ExploitProbability < 0.69 || e.ExploitProbability > 0.71 {
				t.Errorf("edge probability = %v, want ~0.7", e.ExploitProbability)
			}
		}
	}
	if !found {
		t.Errorf("edge %s %s->%s missing from snapshot", ontology.EdgeAffects, cveID, imgID)
	}

	// Injection round-trip: an id/name carrying the old fixed dollar-quote tag,
	// single quotes and backslashes (all attacker-influenceable values) must be
	// stored verbatim — neither corrupting the query nor altering the graph.
	nastyID := `Image:inj-$perspective$')--`
	nastyName := `a'); SELECT drop_graph('x'); --$perspective$ \x`
	must(s.UpsertNode(ctx, ontology.Node{ID: nastyID, Label: ontology.LabelImage, Name: nastyName}), "injection upsert")
	snap, err = s.Snapshot(ctx)
	must(err, "snapshot after injection upsert")
	if n, ok := snap.NodeByID()[nastyID]; !ok {
		t.Errorf("injection-payload node missing — value was not stored verbatim")
	} else if n.Name != nastyName {
		t.Errorf("injection payload mangled: name = %q, want %q", n.Name, nastyName)
	}

	// ── Staleness pruning ───────────────────────────────────────────────
	// Both backends must agree: prune removes elements stale by last_seen (and
	// edges orphaned by a pruned node), keeps fresh ones, and never touches
	// elements that have no last_seen stamp (grandfathered).
	pruner, ok := graph.AsPruner(s)
	if !ok {
		t.Fatal("store does not implement Pruner")
	}
	now := time.Now()
	staleTS := now.Add(-48 * time.Hour).Unix()
	freshTS := now.Unix()
	must(s.UpsertNode(ctx, ontology.Node{ID: "prune-stale", Label: ontology.LabelContainer, Name: "stale",
		Properties: map[string]any{ontology.PropLastSeen: staleTS}}), "stale node upsert")
	must(s.UpsertNode(ctx, ontology.Node{ID: "prune-fresh", Label: ontology.LabelContainer, Name: "fresh",
		Properties: map[string]any{ontology.PropLastSeen: freshTS}}), "fresh node upsert")
	must(s.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeConnectsTo, From: "prune-stale", To: "prune-fresh",
		ExploitProbability: 0.5, Properties: map[string]any{ontology.PropLastSeen: staleTS}}), "stale edge upsert")

	stats, err := pruner.Prune(ctx, now.Add(-24*time.Hour))
	must(err, "prune")
	if stats.Nodes < 1 {
		t.Errorf("prune reported %d nodes removed, want ≥1", stats.Nodes)
	}
	snap, err = s.Snapshot(ctx)
	must(err, "snapshot after prune")
	byID := snap.NodeByID()
	if _, ok := byID["prune-stale"]; ok {
		t.Error("stale node survived prune")
	}
	if _, ok := byID["prune-fresh"]; !ok {
		t.Error("fresh node was wrongly pruned")
	}
	if _, ok := byID[imgID]; !ok {
		t.Error("node without last_seen must NOT be pruned (grandfathered)")
	}
	for _, e := range snap.Edges {
		if e.From == "prune-stale" || e.To == "prune-stale" {
			t.Error("edge incident to a pruned node still present after prune")
		}
	}
}
