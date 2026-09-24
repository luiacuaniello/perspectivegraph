package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/ratelimit"
	"github.com/luiacuaniello/perspectivegraph/internal/remediation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// wideAPI builds n independent routes - load balancer, container, admin role - so the
// paths' remediations cut many distinct edges, and runs the analyzer once. With
// sharedRole the routes end at one role, which a single fix on that role can cut.
func wideAPI(t *testing.T, n int, sharedRole ...bool) *API {
	t.Helper()
	ctx := context.Background()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	store, err := mgr.For(ctx, graph.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	shared := len(sharedRole) > 0 && sharedRole[0]
	ev := ontology.Event{ObservedAt: time.Now()}
	for i := 0; i < n; i++ {
		lb, svc, role := fmt.Sprintf("lb-%d", i), fmt.Sprintf("svc-%d", i), fmt.Sprintf("role-%d", i)
		if shared {
			role = "role"
		}
		ev.Nodes = append(ev.Nodes,
			ontology.Node{ID: lb, Label: ontology.LabelLoadBalancer, Name: lb, Properties: map[string]any{ontology.PropInternetExposed: true}},
			ontology.Node{ID: svc, Label: ontology.LabelContainer, Name: svc},
			ontology.Node{ID: role, Label: ontology.LabelIAMRole, Name: role, Properties: map[string]any{ontology.PropCrownJewel: true}})
		ev.Edges = append(ev.Edges,
			ontology.Edge{Type: ontology.EdgeExposes, From: lb, To: svc, ExploitProbability: 0.9},
			ontology.Edge{Type: ontology.EdgeAssumes, From: svc, To: role, ExploitProbability: 0.8})
	}
	if err := graph.ApplyEvent(ctx, store, ev); err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	svc := analyzer.NewService(mgr, 5*time.Millisecond, nil)
	go func() { _ = svc.Run(runCtx) }()
	deadline := time.Now().Add(10 * time.Second)
	for len(svc.Latest(graph.DefaultTenant)) < n {
		if time.Now().After(deadline) {
			t.Fatalf("analyzer found %d paths, want %d", len(svc.Latest(graph.DefaultTenant)), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return New(mgr, svc, nil)
}

type gqlResponse struct {
	Data   map[string]any `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func postGraphQL(t *testing.T, h http.Handler, q string, header ...string) gqlResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"query": q})
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	if len(header) == 2 {
		r.Header.Set(header[0], header[1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out gqlResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return out
}

// One field in the document, one what-if per list element at run time - which is what
// the static guard cannot see. A request past its budget gets errors for the rest of
// its heavy fields instead of running them all.
func TestARequestCannotRunMoreHeavyAnalysesThanItsBudget(t *testing.T) {
	a := wideAPI(t, 15) // two remediations a route: thirty distinct cuts, past the budget
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	res := postGraphQL(t, h, `{ attackPaths(limit: 100) { remediations { verification { verified } } } }`)

	computed := 0
	for _, p := range res.Data["attackPaths"].([]any) {
		for _, r := range p.(map[string]any)["remediations"].([]any) {
			if r.(map[string]any)["verification"] != nil {
				computed++
			}
		}
	}
	if computed == 0 || computed > requestComputeBudget {
		t.Errorf("%d verifications computed in one request, want between 1 and %d", computed, requestComputeBudget)
	}
	refused := 0
	for _, e := range res.Errors {
		if strings.Contains(e.Message, "heavy analyses") {
			refused++
		}
	}
	if refused == 0 {
		t.Errorf("no budget error for the verifications past the budget; errors: %+v", res.Errors)
	}
}

// Aliasing the same selection costs one computation, not one per alias: the request
// proves each distinct cut once.
func TestRepeatingAVerificationInOneRequestCostsOne(t *testing.T) {
	a := wideAPI(t, 3)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	plan := postGraphQL(t, h, `{ remediationPlan { title } }`)
	fixes := plan.Data["remediationPlan"].([]any)
	if len(fixes) == 0 {
		t.Fatal("empty remediation plan")
	}
	title := fixes[0].(map[string]any)["title"].(string)

	var q strings.Builder
	q.WriteString("{")
	for i := 0; i < 3*requestComputeBudget; i++ {
		fmt.Fprintf(&q, " a%d: remediationPlan(title: %q) { verification { verified } }", i, title)
	}
	q.WriteString(" }")
	res := postGraphQL(t, h, q.String())
	if len(res.Errors) > 0 {
		t.Fatalf("%d aliases of one fix's proof were refused: %v", 3*requestComputeBudget, res.Errors[0].Message)
	}
	for k, v := range res.Data {
		got := v.([]any)
		if len(got) != 1 || got[0].(map[string]any)["verification"] == nil {
			t.Fatalf("%s: %v, want the one fix with its proof", k, got)
		}
	}
}

// remediationPlan(title:) returns that fix alone, with the rank it has in the whole plan:
// it is how the dashboard asks for one proof without paying for every fix's.
func TestRemediationPlanCanBeAskedForOneFix(t *testing.T) {
	a := wideAPI(t, 3)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	all := postGraphQL(t, h, `{ remediationPlan { title coveragePct } }`).Data["remediationPlan"].([]any)
	if len(all) < 2 {
		t.Fatalf("want a plan of several fixes, got %d", len(all))
	}
	want := all[1].(map[string]any)
	one := postGraphQL(t, h, fmt.Sprintf(`{ remediationPlan(title: %q) { title coveragePct } }`, want["title"])).Data["remediationPlan"].([]any)
	if len(one) != 1 || one[0].(map[string]any)["title"] != want["title"] || one[0].(map[string]any)["coveragePct"] != want["coveragePct"] {
		t.Errorf("remediationPlan(title:) = %v, want exactly %v", one, want)
	}
}

// The process-wide cap: with every slot taken, a heavy analysis waits instead of
// running, and gives up with its request.
func TestHeavyAnalysesWaitForAFreeSlot(t *testing.T) {
	a := &API{heavySlots: make(chan struct{}, 1)}
	a.heavySlots <- struct{}{} // someone else's analysis

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ran := false
	_, err := a.heavy(ctx, "k", func(context.Context) (any, error) { ran = true; return nil, nil })
	if ran || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ran=%v err=%v; with no free slot the analysis must wait, then give up with its request", ran, err)
	}

	<-a.heavySlots // the other analysis finishes
	if _, err := a.heavy(context.Background(), "k", func(context.Context) (any, error) { ran = true; return nil, nil }); err != nil || !ran {
		t.Fatalf("ran=%v err=%v once a slot was free", ran, err)
	}
	if len(a.heavySlots) != 0 {
		t.Error("the slot was not released after the analysis")
	}
}

// A read-only public instance gives every visitor the viewer role. The AI answers are
// paid for, so they need a credential - and the dashboard is told, so it does not offer
// a button that answers 403.
func TestAIAnswersNeedASignedInCaller(t *testing.T) {
	a := publicReadOnly(t)
	fa := &fakeAI{enabled: true}
	a.WithAI(fa)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ask := func(header ...string) int {
		r := httptest.NewRequest(http.MethodPost, "/ai/query", strings.NewReader(`{"question":"what is exposed?"}`))
		r.Header.Set("Content-Type", "application/json")
		if len(header) == 2 {
			r.Header.Set(header[0], header[1])
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := ask(); code != http.StatusForbidden {
		t.Errorf("anonymous /ai/query = %d, want 403", code)
	}
	if fa.calls != 0 {
		t.Errorf("the model was called %d time(s) for an anonymous visitor", fa.calls)
	}
	if code := ask("Authorization", "Bearer s3cr3t"); code != http.StatusOK {
		t.Errorf("signed-in /ai/query = %d, want 200", code)
	}

	if got := postGraphQL(t, h, `{ aiEnabled }`).Data["aiEnabled"]; got != false {
		t.Errorf("aiEnabled for an anonymous visitor = %v, want false", got)
	}
	if got := postGraphQL(t, h, `{ aiEnabled }`, "Authorization", "Bearer s3cr3t").Data["aiEnabled"]; got != true {
		t.Errorf("aiEnabled for a signed-in caller = %v, want true", got)
	}
}

// The AI endpoints have their own rate limit, far below the API's.
func TestAIHasItsOwnRateLimit(t *testing.T) {
	a := seededAPI(t)
	a.WithAI(&fakeAI{enabled: true}).WithAIRateLimit(ratelimit.New(1.0/60, 2))
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	codes := []int{}
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest(http.MethodGet, "/ai/summary", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{Subject: "analyst", Role: auth.RoleViewer, Tenant: "default"})))
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Errorf("three calls in a row = %v, want [200 200 429] with a burst of two", codes)
	}
}

// Time is the budget that matters on a large graph, where one analysis can take many
// seconds: once a request's time is up, the analysis running is stopped and the next
// one is refused without starting.
func TestARequestsHeavyAnalysesStopWhenItsTimeIsUp(t *testing.T) {
	a := &API{heavySlots: make(chan struct{}, 1)}
	scope := &computeScope{remaining: requestComputeBudget, deadline: time.Now().Add(100 * time.Millisecond), memo: map[string]any{}}
	ctx := context.WithValue(context.Background(), computeCtxKey{}, scope)

	start := time.Now()
	_, err := a.heavy(ctx, "slow", func(ctx context.Context) (any, error) {
		<-ctx.Done() // a simulation checking its context
		return nil, ctx.Err()
	})
	if !errors.Is(err, errComputeBudget) {
		t.Fatalf("err = %v, want the budget error once the request's time is up", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the analysis ran %v past a 100ms budget", took)
	}
	ran := false
	if _, err := a.heavy(ctx, "next", func(context.Context) (any, error) { ran = true; return nil, nil }); !errors.Is(err, errComputeBudget) || ran {
		t.Fatalf("after the budget: ran=%v err=%v, want refused without running", ran, err)
	}
	if len(a.heavySlots) != 0 {
		t.Error("a stopped analysis kept its slot")
	}
}

// The uncut simulation is half of every fix's proof and the same for all of them, so a
// request proving two fixes runs it once: three analyses, not four.
func TestProvingSeveralFixesSharesOneBaseline(t *testing.T) {
	a := wideAPI(t, 2)
	scope := &computeScope{remaining: requestComputeBudget, deadline: time.Now().Add(time.Minute), memo: map[string]any{}}
	ctx := context.WithValue(viewerCtx(), computeCtxKey{}, scope)
	for _, i := range []int{0, 1} {
		cut := remediation.CutEdge{From: fmt.Sprintf("lb-%d", i), To: fmt.Sprintf("svc-%d", i), Type: string(ontology.EdgeExposes)}
		v, err := a.verifyCut(ctx, cut)
		if err != nil || v == nil {
			t.Fatalf("verify %v: %v %v", cut, v, err)
		}
		if !v.(map[string]any)["verified"].(bool) {
			t.Errorf("cutting %v should provably remove its route: %v", cut, v)
		}
	}
	if spent := requestComputeBudget - scope.remaining; spent != 3 {
		t.Errorf("two proofs spent %d analyses, want 3 (one shared baseline, one per cut)", spent)
	}
}
