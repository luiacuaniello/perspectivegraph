package api

import (
	"context"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// prVerdict exists for one caller: a CI gate deciding whether to fail a build. Its whole
// value is reporting THREE states rather than two, because the two-state version has a
// failure mode this product exists to prevent - a pipeline whose scanner output never
// arrived would get the same answer as a pipeline that is genuinely clean, and would
// report a green light for a commit nobody analysed.

const (
	testSlug = "acme/payments"
	testSHA  = "abc123def456"
)

// verdictAPI seeds an estate where the container carrying the commit sits on an
// internet -> crown-jewel route, then waits for the analyzer to produce paths.
func verdictAPI(t *testing.T, stampCommit bool, reachable bool) *API {
	t.Helper()
	ctx := context.Background()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	store, err := mgr.For(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	svcProps := map[string]any{}
	if stampCommit {
		svcProps[ontology.PropRepoSlug] = testSlug
		svcProps[ontology.PropCommitSHA] = testSHA
	}

	must(store.UpsertNode(ctx, ontology.Node{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-alb",
		Properties: map[string]any{ontology.PropInternetExposed: true}}))
	must(store.UpsertNode(ctx, ontology.Node{ID: "svc", Label: ontology.LabelContainer, Name: "payments", Properties: svcProps}))
	must(store.UpsertNode(ctx, ontology.Node{ID: "role", Label: ontology.LabelIAMRole, Name: "payments-admin",
		Properties: map[string]any{ontology.PropCrownJewel: true}}))

	if reachable {
		must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: "lb", To: "svc", ExploitProbability: 0.9}))
	}
	must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: "svc", To: "role", ExploitProbability: 0.8}))

	runCtx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	svc := analyzer.NewService(mgr, 5*time.Millisecond, nil)
	go func() { _ = svc.Run(runCtx) }()

	// Wait for a pass to complete. When `reachable` is false no path exists, so the
	// signal is the Monte Carlo having run rather than paths having appeared.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if reachable && len(svc.Latest(graph.DefaultTenant)) > 0 {
			break
		}
		if !reachable && svc.LatestRisk(graph.DefaultTenant).Iterations > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("analyzer did not complete a pass within 10s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return New(mgr, svc, nil)
}

const verdictQuery = `{ prVerdict(slug: "acme/payments", sha: "abc123def456") { analysed criticalPaths paths { id } } }`

// The blocking case: the commit is on a route that reaches a crown jewel.
func TestPRVerdictReportsPathsForTheCommit(t *testing.T) {
	got := query(t, verdictAPI(t, true, true), verdictQuery)
	v := got["prVerdict"].(map[string]any)

	if v["analysed"] != true {
		t.Error("a commit whose asset is in the graph is reported as not analysed")
	}
	if n, _ := v["criticalPaths"].(int); n == 0 {
		t.Fatalf("no critical path attributed to the commit: %+v", v)
	}
	if paths, _ := v["paths"].([]any); len(paths) == 0 {
		t.Error("criticalPaths is non-zero but no path was returned, so a gate cannot say what it blocked on")
	}
}

// The clean case, and the one that must NOT look like the unknown case: the commit was
// ingested, the engine looked, and nothing reaches a sensitive asset from it.
func TestPRVerdictSeparatesCleanFromUnknown(t *testing.T) {
	got := query(t, verdictAPI(t, true, false), verdictQuery)
	v := got["prVerdict"].(map[string]any)

	if v["analysed"] != true {
		t.Fatal("an ingested commit with no reachable path is reported as not analysed, which a gate would read as unknown")
	}
	if n, _ := v["criticalPaths"].(int); n != 0 {
		t.Errorf("criticalPaths = %d for an unreachable asset", n)
	}
}

// The unknown case: nothing carrying this commit ever reached the graph. A gate must be
// able to tell this apart from clean, because passing a build on it would be passing a
// build whose scanner output never arrived.
func TestPRVerdictReportsUnknownWhenNothingWasIngested(t *testing.T) {
	got := query(t, verdictAPI(t, false, true), verdictQuery)
	v := got["prVerdict"].(map[string]any)

	if v["analysed"] != false {
		t.Fatal("a commit that was never ingested is reported as analysed, which would let a gate pass a build nobody looked at")
	}
	if n, _ := v["criticalPaths"].(int); n != 0 {
		t.Errorf("criticalPaths = %d for a commit that was never ingested", n)
	}
}

// analysedAt closes the gap between the two sources the verdict reads from: `analysed`
// comes from the graph, `criticalPaths` from the last analyzer pass. A commit can be in
// the graph while the paths still describe the estate as it was before it arrived - which
// reads as zero paths on a commit that has one. A gate compares this against its own
// ingest time and keeps waiting, so the field has to be there and has to be a real time.
func TestPRVerdictDatesTheAnalysis(t *testing.T) {
	before := time.Now().Add(-time.Second)
	got := query(t, verdictAPI(t, true, true), `{ prVerdict(slug: "acme/payments", sha: "abc123def456") { analysedAt } }`)
	v := got["prVerdict"].(map[string]any)

	raw, _ := v["analysedAt"].(string)
	if raw == "" {
		t.Fatal("no analysedAt, so a gate cannot tell a fresh verdict from one that predates its own ingest")
	}
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("analysedAt %q is not RFC 3339: %v", raw, err)
	}
	if at.Before(before) {
		t.Errorf("analysedAt = %s, before the test even started", at)
	}
}

// A commit belonging to a different repository must not match on the SHA alone.
func TestPRVerdictMatchesSlugAndShaTogether(t *testing.T) {
	a := verdictAPI(t, true, true)
	got := query(t, a, `{ prVerdict(slug: "other/repo", sha: "abc123def456") { analysed criticalPaths } }`)
	v := got["prVerdict"].(map[string]any)
	if v["analysed"] != false {
		t.Error("matched a different repository on the SHA alone")
	}

	got = query(t, a, `{ prVerdict(slug: "acme/payments", sha: "0000000000") { analysed criticalPaths } }`)
	v = got["prVerdict"].(map[string]any)
	if v["analysed"] != false {
		t.Error("matched a different commit on the slug alone")
	}
}
