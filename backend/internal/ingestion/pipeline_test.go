package ingestion_test

// Integration tests for the correlation pipeline, exercised end-to-end minus the
// bus and database: real testdata files → collectors → in-memory graph →
// attack-path analyzer. This is the behaviour `make seed` triggers against the
// running stack.

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/aegisgraph/aegisgraph/internal/analyzer"
	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/internal/graph/memory"
	"github.com/aegisgraph/aegisgraph/internal/ingestion"
	"github.com/aegisgraph/aegisgraph/internal/ingestion/falco"
	"github.com/aegisgraph/aegisgraph/internal/ingestion/semgrep"
	"github.com/aegisgraph/aegisgraph/internal/ingestion/trivy"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

// Trivy + infra context correlate into the Log4Shell → admin-role path. The
// SAST-only crown jewel (customers-db) stays unreachable without Semgrep.
func TestCorrelatedAttackPath(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	applyContext(t, ctx, store)
	applyTrivy(t, ctx, store)

	paths := snapshotPaths(t, ctx, store)
	if len(paths) != 1 {
		t.Fatalf("expected 1 correlated attack path, got %d", len(paths))
	}
	p := paths[0]

	// LB(internet) →EXPOSES(.9)→ Container →HOSTS(.95)→ Image →DEPENDS_ON(.95)→
	// log4j →AFFECTS(.9)→ CVE-2021-44228 →EXPLOITS(.8)→ admin role
	want := 0.9 * 0.95 * 0.95 * 0.9 * 0.8
	assertScore(t, p, want)
	if p.Target().Label != ontology.LabelIAMRole {
		t.Errorf("target label = %s, want IAM_Role", p.Target().Label)
	}
}

// Adding Semgrep yields a SECOND, independent path: an internet-reachable code
// weakness (command injection) that leads to the customers PII database. This
// is the cross-tool correlation that is AegisGraph's whole point.
func TestThreeToolCorrelation(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	applyContext(t, ctx, store)
	applyTrivy(t, ctx, store)
	applySemgrep(t, ctx, store)

	paths := snapshotPaths(t, ctx, store)
	if len(paths) != 2 {
		t.Fatalf("expected 2 attack paths (one per crown jewel), got %d", len(paths))
	}

	byTarget := map[ontology.Label]analyzer.AttackPath{}
	for _, p := range paths {
		byTarget[p.Target().Label] = p
	}

	// Path A — Trivy/Log4Shell → admin IAM role.
	rolePath, ok := byTarget[ontology.LabelIAMRole]
	if !ok {
		t.Fatal("missing path to IAM_Role")
	}
	assertScore(t, rolePath, 0.9*0.95*0.95*0.9*0.8)

	// Path B — Semgrep/command-injection → customers PII database.
	// LB →EXPOSES(.9)→ Container →HOSTS(.95)→ Image →BUILT_FROM(.9)→ repo
	//    →AFFECTS(.8 = ERROR×HIGH)→ Weakness →EXPLOITS(.7)→ customers-db
	dbPath, ok := byTarget[ontology.LabelVirtualMachine]
	if !ok {
		t.Fatal("missing path to customers-db (VirtualMachine)")
	}
	assertScore(t, dbPath, 0.9*0.95*0.9*0.8*0.7)

	var weaknessSeen bool
	for _, n := range dbPath.Nodes {
		if n.Label == ontology.LabelWeakness {
			weaknessSeen = true
		}
	}
	if !weaknessSeen {
		t.Error("SAST path should traverse a Weakness node")
	}
	t.Logf("path A (%.2f): %s", rolePath.Score, pathString(rolePath))
	t.Logf("path B (%.2f): %s", dbPath.Score, pathString(dbPath))
}

// Adding Falco runtime alerts on the payments container (which both paths
// traverse) flips both paths to runtime-confirmed — the responder's signal that
// these aren't theoretical, they're being exercised right now.
func TestRuntimeConfirmation(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	applyContext(t, ctx, store)
	applyTrivy(t, ctx, store)
	applySemgrep(t, ctx, store)
	applyFalco(t, ctx, store)

	paths := snapshotPaths(t, ctx, store)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}
	for _, p := range paths {
		if !p.RuntimeConfirmed {
			t.Errorf("path to %s should be runtime-confirmed by the Falco alert", p.Target().Name)
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────

func applyContext(t *testing.T, ctx context.Context, store graph.Store) {
	t.Helper()
	data, err := os.ReadFile("../../testdata/context.json")
	if err != nil {
		t.Fatal(err)
	}
	var ev ontology.Event
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatalf("decode context: %v", err)
	}
	if err := graph.ApplyEvent(ctx, store, ev); err != nil {
		t.Fatalf("apply context: %v", err)
	}
}

func applyTrivy(t *testing.T, ctx context.Context, store graph.Store) {
	t.Helper()
	applyReport(t, ctx, store, trivy.New(), "../../testdata/trivy-sample.json", ingestion.Options{})
}

func applySemgrep(t *testing.T, ctx context.Context, store graph.Store) {
	t.Helper()
	applyReport(t, ctx, store, semgrep.New(), "../../testdata/semgrep-sample.json",
		ingestion.Options{Repository: "payments-api"})
}

func applyFalco(t *testing.T, ctx context.Context, store graph.Store) {
	t.Helper()
	applyReport(t, ctx, store, falco.New(), "../../testdata/falco-sample.json", ingestion.Options{})
}

func applyReport(t *testing.T, ctx context.Context, store graph.Store, c ingestion.Collector, path string, opts ingestion.Options) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := c.Parse(f, opts)
	if err != nil {
		t.Fatalf("%s parse: %v", c.Source(), err)
	}
	for _, ev := range events {
		if err := graph.ApplyEvent(ctx, store, ev); err != nil {
			t.Fatalf("apply %s: %v", c.Source(), err)
		}
	}
}

func snapshotPaths(t *testing.T, ctx context.Context, store graph.Store) []analyzer.AttackPath {
	t.Helper()
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return analyzer.FindCriticalPaths(snap)
}

func assertScore(t *testing.T, p analyzer.AttackPath, want float64) {
	t.Helper()
	if math.Abs(p.Score-want) > 1e-9 {
		t.Errorf("path %s score = %.5f, want %.5f", p.ID, p.Score, want)
	}
	if !p.Source().Bool(ontology.PropInternetExposed) {
		t.Errorf("path %s should start at an internet-exposed node", p.ID)
	}
	if !p.Target().Bool(ontology.PropCrownJewel) {
		t.Errorf("path %s should end at a crown-jewel node", p.ID)
	}
}

func pathString(p analyzer.AttackPath) string {
	s := ""
	for i, n := range p.Nodes {
		if i > 0 {
			s += " → "
		}
		s += n.Name
	}
	return s
}
