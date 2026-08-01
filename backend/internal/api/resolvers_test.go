package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/graphql-go/graphql"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// seededAPI builds an API over a small but complete estate: an internet-exposed load
// balancer reaching an admin role through a container, plus a second app so the
// application-scoping resolvers have something to separate. The analyzer is run once,
// so attackPaths and the posture resolvers answer with real data rather than zeroes -
// an empty graph exercises the resolvers' early returns and nothing else.
func seededAPI(t *testing.T) *API {
	t.Helper()
	ctx := context.Background()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatalf("graph manager: %v", err)
	}
	store, err := mgr.For(ctx, "default")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(store.UpsertNode(ctx, ontology.Node{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-alb",
		Properties: map[string]any{ontology.PropInternetExposed: true, "app": "payments-api"}}))
	must(store.UpsertNode(ctx, ontology.Node{ID: "svc", Label: ontology.LabelContainer, Name: "payments",
		Properties: map[string]any{"app": "payments-api"}}))
	must(store.UpsertNode(ctx, ontology.Node{ID: "role", Label: ontology.LabelIAMRole, Name: "payments-admin",
		Properties: map[string]any{ontology.PropCrownJewel: true, "app": "payments-api"}}))
	// A second application, entirely disconnected, so app scoping has a negative case.
	must(store.UpsertNode(ctx, ontology.Node{ID: "billing", Label: ontology.LabelContainer, Name: "billing",
		Properties: map[string]any{"app": "billing-api"}}))

	must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: "lb", To: "svc", ExploitProbability: 0.9}))
	must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: "svc", To: "role", ExploitProbability: 0.8}))

	// Service.Run is the daemon loop, not a single pass, and the single-pass method is
	// unexported. So drive it the way production does - on a tick - and wait for the
	// first pass to land before querying, then stop it so the test leaves nothing running.
	runCtx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	svc := analyzer.NewService(mgr, 5*time.Millisecond, nil)
	go func() { _ = svc.Run(runCtx) }()

	deadline := time.Now().Add(10 * time.Second)
	for len(svc.Latest(graph.DefaultTenant)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("analyzer produced no attack path for the seeded estate within 10s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return New(mgr, svc, nil)
}

// query executes a GraphQL request and fails the test on any GraphQL error, so a
// resolver that panics or errors cannot be mistaken for one that returned nothing.
func query(t *testing.T, a *API, q string, ctxs ...context.Context) map[string]any {
	t.Helper()
	schema, err := a.Schema()
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	ctx := viewerCtx()
	if len(ctxs) > 0 {
		ctx = ctxs[0]
	}
	res := graphql.Do(graphql.Params{Schema: schema, RequestString: q, Context: ctx})
	if len(res.Errors) > 0 {
		t.Fatalf("query %q: %v", q, res.Errors)
	}
	m, _ := res.Data.(map[string]any)
	return m
}

func TestAttackPathsResolverReturnsTheRouteAndItsFields(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ attackPaths { id score priority priorityLabel runtimeConfirmed
	    nodes { id name label } steps { from to edgeType probability } } }`)

	paths, _ := data["attackPaths"].([]any)
	if len(paths) == 0 {
		t.Fatal("no attack paths: the seeded internet → crown-jewel route was not found")
	}
	p, _ := paths[0].(map[string]any)
	if p["id"] == "" || p["id"] == nil {
		t.Error("path has no id")
	}
	nodes, _ := p["nodes"].([]any)
	if len(nodes) < 2 {
		t.Fatalf("path has %d nodes, want the full route", len(nodes))
	}
	first, _ := nodes[0].(map[string]any)
	if first["name"] != "edge-alb" {
		t.Errorf("route does not start at the internet-exposed asset: %v", first["name"])
	}
	if steps, _ := p["steps"].([]any); len(steps) == 0 {
		t.Error("path exposes no steps, so the kill chain would render empty")
	}
}

// limit is what keeps a real estate's thousands of paths from being serialized into
// every dashboard poll, so it has to actually bound the result.
func TestAttackPathsRespectsLimit(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ attackPaths(limit: 1) { id } }`)
	if paths, _ := data["attackPaths"].([]any); len(paths) > 1 {
		t.Fatalf("limit: 1 returned %d paths", len(paths))
	}
}

func TestPostureResolverCountsTheEstate(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ posture { nodes edges activePaths criticalPaths suppressedPaths runtimeConfirmed } }`)
	p, _ := data["posture"].(map[string]any)
	if p == nil {
		t.Fatal("posture resolved to nothing")
	}
	if n, _ := p["nodes"].(int); n < 4 {
		t.Errorf("posture reports %v nodes, want the 4 seeded", p["nodes"])
	}
	if ap, _ := p["activePaths"].(int); ap < 1 {
		t.Errorf("posture reports %v active paths, want at least 1", p["activePaths"])
	}
}

func TestGraphResolverReturnsNodesAndEdges(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ graph { nodes { id name label } edges { from to type } } }`)
	g, _ := data["graph"].(map[string]any)
	nodes, _ := g["nodes"].([]any)
	edges, _ := g["edges"].([]any)
	if len(nodes) != 4 || len(edges) != 2 {
		t.Fatalf("graph returned %d nodes / %d edges, want 4 / 2", len(nodes), len(edges))
	}
}

// The app argument is the dashboard's scope selector: it must narrow the graph to the
// chosen application rather than returning everything.
func TestGraphResolverFiltersByApplication(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ graph(app: "billing-api") { nodes { name } } }`)
	g, _ := data["graph"].(map[string]any)
	nodes, _ := g["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("scoping to billing-api returned %d nodes, want 1", len(nodes))
	}
	n, _ := nodes[0].(map[string]any)
	if n["name"] != "billing" {
		t.Errorf("scoped graph returned %v", n["name"])
	}
}

func TestGraphResolverPaginates(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ graph(limit: 2) { nodes { id } } }`)
	g, _ := data["graph"].(map[string]any)
	if nodes, _ := g["nodes"].([]any); len(nodes) != 2 {
		t.Fatalf("limit: 2 returned %d nodes", len(nodes))
	}
}

func TestApplicationsResolverListsBothApps(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ applications }`)
	apps, _ := data["applications"].([]any)
	if len(apps) != 2 {
		t.Fatalf("applications = %v, want the two seeded", apps)
	}
	if apps[0] != "billing-api" || apps[1] != "payments-api" {
		t.Errorf("applications = %v, want them sorted", apps)
	}
}

// Object-level RBAC through the resolver, not just the helper: a principal restricted
// to billing-api must not see the payments route, which is the whole point of Apps.
func TestAttackPathsAreScopedToThePrincipalsApps(t *testing.T) {
	a := seededAPI(t)
	restricted := auth.WithPrincipal(context.Background(), auth.Principal{
		Subject: "billing-bot", Role: auth.RoleViewer, Tenant: "default", Apps: []string{"billing-api"},
	})
	data := query(t, a, `{ attackPaths { id nodes { name } } }`, restricted)
	if paths, _ := data["attackPaths"].([]any); len(paths) != 0 {
		t.Fatalf("a billing-scoped principal saw %d payments paths", len(paths))
	}

	// And the unrestricted principal still sees it, so the filter is scoping rather
	// than a blanket denial.
	if paths, _ := query(t, a, `{ attackPaths { id } }`)["attackPaths"].([]any); len(paths) == 0 {
		t.Fatal("the unrestricted principal now sees nothing either")
	}
}

func TestRiskSimulationResolverProducesABand(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ riskSimulation { iterations anyCompromiseProbability sensitivityLow sensitivityHigh
	    expectedCompromised crownJewels { name compromiseProbability } } }`)
	r, _ := data["riskSimulation"].(map[string]any)
	if r == nil {
		t.Fatal("riskSimulation resolved to nothing")
	}
	lo, _ := r["sensitivityLow"].(float64)
	hi, _ := r["sensitivityHigh"].(float64)
	if hi < lo {
		t.Errorf("sensitivity band is inverted: %v..%v", lo, hi)
	}
	if jewels, _ := r["crownJewels"].([]any); len(jewels) == 0 {
		t.Error("no crown jewels reported despite one being seeded")
	}
}

func TestRemediationPlanResolverProposesAFix(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ remediationPlan { title kind pathCount coveragePct } }`)
	plan, _ := data["remediationPlan"].([]any)
	if len(plan) == 0 {
		t.Fatal("a reachable crown-jewel route produced no remediation")
	}
	f, _ := plan[0].(map[string]any)
	if f["title"] == "" || f["title"] == nil {
		t.Error("fix has no title")
	}
}

// whatIf is the resolver behind "what if I cut this edge": it must re-run the analysis
// with the cut applied and report fewer paths, or the feature is decorative.
func TestWhatIfCuttingTheEntryEdgeRemovesThePath(t *testing.T) {
	a := seededAPI(t)
	before := query(t, a, `{ attackPaths { id } }`)
	n0 := len(before["attackPaths"].([]any))

	data := query(t, a, `{ whatIf(cuts: [{from: "edge-alb", to: "payments", type: "EXPOSES"}]) {
	    before { id } after { id } removedEdges riskReduction } }`)
	w, _ := data["whatIf"].(map[string]any)
	if w == nil {
		t.Fatal("whatIf resolved to nothing")
	}
	if re, _ := w["removedEdges"].(int); re < 1 {
		t.Errorf("removedEdges = %v: the named edge was not matched", w["removedEdges"])
	}
	after, _ := w["after"].([]any)
	if len(after) >= n0 {
		t.Fatalf("cutting the entry edge left %d paths (was %d): the cut was not applied", len(after), n0)
	}
}

func TestCalibrationResolverIsWellFormedWithoutVerdicts(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ calibration { hasData verdict samples brier ece bins { low high count } } }`)
	c, _ := data["calibration"].(map[string]any)
	if c == nil {
		t.Fatal("calibration resolved to nothing")
	}
	if c["hasData"] != false {
		t.Errorf("hasData = %v with no verdicts recorded", c["hasData"])
	}
	if c["verdict"] != "insufficient-data" {
		t.Errorf("verdict = %v, want insufficient-data - a score you cannot check must not claim one", c["verdict"])
	}
	if bins, _ := c["bins"].([]any); len(bins) == 0 {
		t.Error("no reliability bins returned, so the diagram would have nothing to draw")
	}
}

// The invariant resolver is what turns a policy into a red PR check, so a graph that
// violates one has to report it through the API.
func TestInvariantViolationsResolverAnswers(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ invariantViolations { invariantId severity } }`)
	if _, ok := data["invariantViolations"]; !ok {
		t.Fatal("invariantViolations did not resolve")
	}
}

// A malformed query must come back as a GraphQL error, not a panic that takes the
// process with it - the endpoint is reachable by anything that can reach the API.
func TestUnknownFieldIsAnErrorNotAPanic(t *testing.T) {
	a := seededAPI(t)
	schema, err := a.Schema()
	if err != nil {
		t.Fatal(err)
	}
	res := graphql.Do(graphql.Params{Schema: schema, RequestString: `{ noSuchField }`, Context: viewerCtx()})
	if len(res.Errors) == 0 {
		t.Fatal("an unknown field produced no error")
	}
	if !strings.Contains(res.Errors[0].Message, "noSuchField") {
		t.Errorf("error does not name the offending field: %v", res.Errors[0])
	}
}

// The whole response has to survive JSON encoding: the resolvers return internal types,
// and one that cannot marshal would break the endpoint only in production.
func TestTheFullDashboardQueryMarshalsToJSON(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{
	    posture { nodes edges activePaths }
	    attackPaths(limit: 5) { id score nodes { name } }
	    remediationPlan { title }
	    riskSimulation { anyCompromiseProbability }
	    calibration { verdict }
	    applications
	}`)
	if _, err := json.Marshal(data); err != nil {
		t.Fatalf("the dashboard's own query does not marshal: %v", err)
	}
}
