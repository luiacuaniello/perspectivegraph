package api

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func node(id, name string, props map[string]any) ontology.Node {
	return ontology.Node{ID: id, Name: name, Label: ontology.LabelContainer, Properties: props}
}

func snapOf(nodes []ontology.Node, edges []ontology.Edge) graph.Snapshot {
	return graph.Snapshot{Nodes: nodes, Edges: edges}
}

// ── resolveNodeRef ──────────────────────────────────────────────────────────

// A what-if cut is written by a human, who will type the asset's NAME, not the
// content-addressed id the graph uses internally. Resolving the name is what makes
// `cuts: [{from: "edge-alb", ...}]` work at all; an id must pass through untouched.
func TestResolveNodeRefPrefersIDThenName(t *testing.T) {
	snap := snapOf([]ontology.Node{
		node("Container:abc123", "payments", nil),
		node("Container:def456", "billing", nil),
	}, nil)

	if got := resolveNodeRef(snap, "Container:abc123"); got != "Container:abc123" {
		t.Errorf("an existing id was rewritten to %q", got)
	}
	if got := resolveNodeRef(snap, "billing"); got != "Container:def456" {
		t.Errorf("name lookup returned %q, want the node's id", got)
	}
	if got := resolveNodeRef(snap, ""); got != "" {
		t.Errorf("empty ref returned %q", got)
	}
	// An unknown ref is passed through rather than dropped: the analyzer then simply
	// finds no such edge, which is a truthful "that cut changes nothing" instead of a
	// silently different query.
	if got := resolveNodeRef(snap, "not-in-the-graph"); got != "not-in-the-graph" {
		t.Errorf("unknown ref became %q", got)
	}
}

// An id that also happens to be some other node's name must resolve as the id - the
// exact match wins, or a cut could be silently retargeted at a different asset.
func TestResolveNodeRefIDWinsOverANameCollision(t *testing.T) {
	snap := snapOf([]ontology.Node{
		node("payments", "something-else", nil),
		node("Container:xyz", "payments", nil),
	}, nil)
	if got := resolveNodeRef(snap, "payments"); got != "payments" {
		t.Errorf("resolved to %q; the exact id match must win", got)
	}
}

// ── parseCuts ───────────────────────────────────────────────────────────────

func TestParseCutsResolvesEachEndpoint(t *testing.T) {
	resolve := func(s string) string {
		if s == "edge-alb" {
			return "LoadBalancer:1"
		}
		return s
	}
	raw := []any{
		map[string]any{"from": "edge-alb", "to": "payments", "type": "CONNECTS_TO"},
	}
	cuts := parseCuts(raw, resolve)
	if len(cuts) != 1 {
		t.Fatalf("parsed %d cuts, want 1", len(cuts))
	}
	if cuts[0].From != "LoadBalancer:1" || cuts[0].To != "payments" {
		t.Errorf("endpoints not resolved: %+v", cuts[0])
	}
	if cuts[0].Type != ontology.EdgeType("CONNECTS_TO") {
		t.Errorf("type = %q", cuts[0].Type)
	}
}

// GraphQL hands the resolver `any`; anything that is not the expected shape has to be
// skipped rather than panic the query.
func TestParseCutsSurvivesJunkInput(t *testing.T) {
	id := func(s string) string { return s }
	for _, raw := range []any{nil, "a string", 42, []any{"not a map", 7, nil}} {
		if got := parseCuts(raw, id); len(got) != 0 {
			t.Errorf("input %v produced %d cuts, want 0", raw, len(got))
		}
	}
	// A partially-formed cut yields zero-valued fields rather than being dropped, so
	// the caller sees a cut that matches nothing instead of silently fewer cuts.
	got := parseCuts([]any{map[string]any{"from": "a"}}, id)
	if len(got) != 1 || got[0].From != "a" || got[0].To != "" {
		t.Errorf("partial cut parsed as %+v", got)
	}
}

// ── application scoping (object-level RBAC) ─────────────────────────────────

// Application scoping is object-level RBAC: a principal restricted to one app must not
// see attack paths through another. The match is per-path, and a path counts as in-app
// if ANY of its hops belongs to it - a route that passes through the app is the app's
// problem even when it ends elsewhere.
func TestPathMatchesAppOnAnyHop(t *testing.T) {
	p := analyzer.AttackPath{Nodes: []ontology.Node{
		node("n1", "edge-alb", nil),
		node("n2", "payments", map[string]any{"app": "payments-api"}),
		node("n3", "db", nil),
	}}
	if !pathMatchesApp(p, "payments-api") {
		t.Error("a path whose middle hop is in the app did not match")
	}
	if pathMatchesApp(p, "billing-api") {
		t.Error("a path with no hop in the app matched anyway - scoping would leak")
	}
}

// The matcher answers literally - "does this path touch any of THESE apps" - so an
// empty list matches nothing. "Unrestricted" is deliberately not encoded here: the
// callers guard with `if apps := allowedApps(ctx); len(apps) > 0` and skip filtering
// entirely. Making the matcher return true for an empty list would look like a
// harmless fix and would instead hand an app-scoped principal the whole estate the
// moment any caller forgot that guard.
func TestPathMatchesAnyAppIsLiteralAndLeavesUnrestrictedToTheCaller(t *testing.T) {
	p := analyzer.AttackPath{Nodes: []ontology.Node{node("n1", "x", map[string]any{"app": "payments-api"})}}
	if pathMatchesAnyApp(p, nil) {
		t.Error("an empty app list matched; unrestricted access must come from the caller's guard, not from here")
	}
	if !pathMatchesAnyApp(p, []string{"billing-api", "payments-api"}) {
		t.Error("a path in the second of two allowed apps did not match")
	}
}

// ── applications ────────────────────────────────────────────────────────────

// The application list drives the dashboard's scope selector, so it has to be the
// deduplicated, sorted union of both properties that name an app.
func TestApplicationsIsTheSortedUnionOfBothProperties(t *testing.T) {
	snap := snapOf([]ontology.Node{
		node("n1", "a", map[string]any{ontology.PropRepoSlug: "acme/web"}),
		node("n2", "b", map[string]any{"app": "payments-api"}),
		node("n3", "c", map[string]any{ontology.PropRepoSlug: "acme/web"}), // duplicate
		node("n4", "d", map[string]any{"app": ""}),                         // empty is not an app
		node("n5", "e", nil),
	}, nil)

	got := applications(snap)
	want := []string{"acme/web", "payments-api"}
	if len(got) != len(want) {
		t.Fatalf("applications() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("applications() = %v, want %v (sorted, deduplicated)", got, want)
		}
	}
}

func TestApplicationsIsEmptyForAnUnlabelledGraph(t *testing.T) {
	if got := applications(snapOf([]ontology.Node{node("n1", "a", nil)}, nil)); len(got) != 0 {
		t.Errorf("applications() = %v, want none", got)
	}
}

// ── paginate ────────────────────────────────────────────────────────────────

// Pagination exists because a real estate is thousands of nodes. Two properties matter:
// a page is stable (sorted by id, so page 2 does not repeat page 1), and the edges
// returned are only those whose endpoints are both on the page - otherwise the client
// renders edges into nodes it was never given.
func TestPaginateReturnsAStablePageAndOnlyItsEdges(t *testing.T) {
	nodes := []ontology.Node{
		node("n3", "c", nil), node("n1", "a", nil), node("n4", "d", nil), node("n2", "b", nil),
	}
	edges := []ontology.Edge{
		{Type: ontology.EdgeHosts, From: "n1", To: "n2"}, // inside page 1
		{Type: ontology.EdgeHosts, From: "n2", To: "n3"}, // straddles the boundary
		{Type: ontology.EdgeHosts, From: "n3", To: "n4"}, // inside page 2
	}
	snapNodes, snapEdges := paginate(nodes, edges, 2, 0)
	if len(snapNodes) != 2 || snapNodes[0].ID != "n1" || snapNodes[1].ID != "n2" {
		t.Fatalf("page 1 = %v, want n1,n2 in id order", ids(snapNodes))
	}
	if len(snapEdges) != 1 || snapEdges[0].From != "n1" {
		t.Fatalf("page 1 edges = %+v, want only the one wholly inside the page", snapEdges)
	}

	page2, _ := paginate(nodes, edges, 2, 2)
	if len(page2) != 2 || page2[0].ID != "n3" {
		t.Fatalf("page 2 = %v, want n3,n4", ids(page2))
	}
}

func TestPaginateIsAPassthroughWithoutLimitOrOffset(t *testing.T) {
	nodes := []ontology.Node{node("n2", "b", nil), node("n1", "a", nil)}
	got, _ := paginate(nodes, nil, 0, 0)
	if len(got) != 2 || got[0].ID != "n2" {
		t.Errorf("unpaginated call reordered or trimmed: %v", ids(got))
	}
}

// An offset past the end is a client that scrolled too far, not an error: it gets an
// empty page rather than a panic.
func TestPaginateHandlesAnOffsetPastTheEnd(t *testing.T) {
	nodes := []ontology.Node{node("n1", "a", nil)}
	got, gotEdges := paginate(nodes, nil, 10, 99)
	if len(got) != 0 || len(gotEdges) != 0 {
		t.Errorf("offset past the end returned %d nodes, %d edges", len(got), len(gotEdges))
	}
}

func ids(ns []ontology.Node) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.ID
	}
	return out
}
