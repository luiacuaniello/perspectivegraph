package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The governance stores are keyed by path id and were scoped by TENANT alone, while the
// path reads behind them are scoped by tenant AND application. So an admin scoped to one
// application could suppress a path belonging to another team's - hiding a real finding
// from the people responsible for it, silently - and could read the whole tenant's
// boards. docs/MANUAL.md calls the application scope "enforced once at the data boundary,
// no bypass", which these tests are what makes true.

// twoAppAPI seeds one live attack path per application ("payments" and "web") and
// returns their path ids.
func twoAppAPI(t *testing.T) (a *API, paymentsPath, webPath string) {
	t.Helper()
	ctx := context.Background()
	m, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	sup, err := suppress.New("")
	if err != nil {
		t.Fatal(err)
	}
	tk, err := ticket.New("", "")
	if err != nil {
		t.Fatal(err)
	}
	vs, err := validation.New("")
	if err != nil {
		t.Fatal(err)
	}
	a = New(m, analyzer.NewService(m, 50*time.Millisecond, nil), nil).
		WithSuppress(sup).WithTickets(tk).WithValidation(vs)

	store, err := a.manager.For(ctx, auth.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, app := range []string{"payments", "web"} {
		props := map[string]any{"app": app}
		must(store.UpsertNode(ctx, ontology.Node{ID: "lb-" + app, Label: ontology.LabelLoadBalancer,
			Name: "alb-" + app, Properties: mergeProps(props, map[string]any{ontology.PropInternetExposed: true})}))
		must(store.UpsertNode(ctx, ontology.Node{ID: "db-" + app, Label: ontology.LabelDatabase,
			Name: app + "-secrets-db", Properties: mergeProps(props, map[string]any{ontology.PropCrownJewel: true})}))
		must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes,
			From: "lb-" + app, To: "db-" + app, ExploitProbability: 0.9}))
	}

	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = a.analyzer.Run(runCtx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (paymentsPath == "" || webPath == "") {
		for _, p := range a.analyzer.Latest(auth.DefaultTenant) {
			switch {
			case strings.Contains(p.Target().Name, "payments"):
				paymentsPath = p.ID
			case strings.Contains(p.Target().Name, "web"):
				webPath = p.ID
			}
		}
		if paymentsPath != "" && webPath != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if paymentsPath == "" || webPath == "" {
		t.Fatalf("analyzer produced payments=%q web=%q, want both", paymentsPath, webPath)
	}
	return a, paymentsPath, webPath
}

func mergeProps(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func scopedAdmin(app string) context.Context {
	return auth.WithPrincipal(context.Background(), auth.Principal{
		Subject: app + "-admin", Role: auth.RoleAdmin, Tenant: auth.DefaultTenant, Apps: []string{app}})
}

func unscopedAdmin() context.Context {
	return auth.WithPrincipal(context.Background(), auth.Principal{
		Subject: "root", Role: auth.RoleAdmin, Tenant: auth.DefaultTenant})
}

func post(t *testing.T, h http.HandlerFunc, ctx context.Context, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, target, strings.NewReader(body)).WithContext(ctx))
	return rec
}

// The finding, as a guard: suppressing another application's path hides it from the team
// that owns it.
func TestAppScopedAdminCannotSuppressAnotherAppsPath(t *testing.T) {
	a, _, webPath := twoAppAPI(t)

	rec := post(t, a.putSuppression, scopedAdmin("payments"), "/suppressions",
		`{"pathId":"`+webPath+`","reason":"accept-risk","owner":"attacker","ttlDays":365}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("suppressing another app's path returned %d, want 404: %s", rec.Code, rec.Body)
	}

	// The board must not show it either, whichever way it got there.
	rec = post(t, a.putSuppression, unscopedAdmin(), "/suppressions",
		`{"pathId":"`+webPath+`","reason":"accept-risk","owner":"platform","ttlDays":365}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("unscoped admin could not suppress: %d %s", rec.Code, rec.Body)
	}
	list := httptest.NewRecorder()
	a.listSuppressions(list, httptest.NewRequest(http.MethodGet, "/suppressions", nil).WithContext(scopedAdmin("payments")))
	var got struct {
		Suppressions []suppress.Record `json:"suppressions"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Suppressions) != 0 {
		t.Errorf("payments-scoped board shows %d record(s) from another app: %+v", len(got.Suppressions), got.Suppressions)
	}
}

func TestAppScopedAdminCannotTicketOrValidateAnotherAppsPath(t *testing.T) {
	a, paymentsPath, webPath := twoAppAPI(t)
	ctx := scopedAdmin("payments")

	if rec := post(t, a.createTicket, ctx, "/tickets",
		`{"pathId":"`+webPath+`","title":"t","owner":"o"}`); rec.Code != http.StatusNotFound {
		t.Errorf("ticket on another app's path returned %d, want 404: %s", rec.Code, rec.Body)
	}
	if rec := post(t, a.putValidation, ctx, "/validations",
		`{"pathId":"`+webPath+`","outcome":"confirmed","source":"redteam"}`); rec.Code != http.StatusNotFound {
		t.Errorf("validation on another app's path returned %d, want 404: %s", rec.Code, rec.Body)
	}
	// Its own application still works - the scope bounds the caller, it does not break it.
	if rec := post(t, a.createTicket, ctx, "/tickets",
		`{"pathId":"`+paymentsPath+`","title":"t","owner":"o"}`); rec.Code != http.StatusOK {
		t.Errorf("ticket on its OWN path returned %d, want 200: %s", rec.Code, rec.Body)
	}
	if rec := post(t, a.putValidation, ctx, "/validations",
		`{"pathId":"`+paymentsPath+`","outcome":"confirmed","source":"redteam"}`); rec.Code != http.StatusOK {
		t.Errorf("validation on its OWN path returned %d, want 200: %s", rec.Code, rec.Body)
	}
}

// matchPath resolves a path id from a SUBSTRING of a crown-jewel name, so unscoped it is
// an oracle: try one letter at a time and read back the target names of applications the
// caller cannot see.
func TestMatchPathDoesNotResolveAnotherAppsTarget(t *testing.T) {
	a, paymentsPath, _ := twoAppAPI(t)
	ctx := scopedAdmin("payments")

	if got := a.matchPath(ctx, "web-secrets", ""); got != "" {
		t.Errorf("matchPath resolved another app's target: %q", got)
	}
	// A single letter matches every target in the tenant; it must still only return one
	// the caller owns.
	if got := a.matchPath(ctx, "s", ""); got != "" && got != paymentsPath {
		t.Errorf("matchPath(%q) = %q, want empty or the payments path", "s", got)
	}
	if got := a.matchPath(ctx, "payments-secrets", ""); got != paymentsPath {
		t.Errorf("matchPath on its own target = %q, want %q", got, paymentsPath)
	}
}

// Most deployments are one team with no `apps` claim at all. They must be untouched:
// nil from scopedPathIDs means every call site skips the filtering entirely.
func TestUnscopedPrincipalSeesAndActsOnEverything(t *testing.T) {
	a, paymentsPath, webPath := twoAppAPI(t)
	ctx := unscopedAdmin()

	if ids := a.scopedPathIDs(ctx); ids != nil {
		t.Fatalf("an unrestricted caller got a filter set of %d id(s); it must be nil", len(ids))
	}
	for _, id := range []string{paymentsPath, webPath} {
		if !a.mayActOnPath(ctx, id) {
			t.Errorf("unrestricted caller refused path %s", id)
		}
		if rec := post(t, a.putSuppression, ctx, "/suppressions",
			`{"pathId":"`+id+`","reason":"accept-risk","owner":"platform","ttlDays":1}`); rec.Code != http.StatusOK {
			t.Errorf("unrestricted suppress of %s returned %d: %s", id, rec.Code, rec.Body)
		}
	}
	list := httptest.NewRecorder()
	a.listSuppressions(list, httptest.NewRequest(http.MethodGet, "/suppressions", nil).WithContext(ctx))
	var got struct {
		Suppressions []suppress.Record `json:"suppressions"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Suppressions) != 2 {
		t.Errorf("unrestricted board shows %d record(s), want 2", len(got.Suppressions))
	}
}

// A verdict names a path id, and the features the server captures describe that path.
// An app-scoped caller must not be able to read another application's score by naming
// its id - pathFeatures took the tenant alone, which is exactly what let it.
func TestPathFeaturesAreScopedToTheCallersApps(t *testing.T) {
	a, paymentsPath, webPath := twoAppAPI(t)
	ctx := scopedAdmin("payments")

	if _, _, _, _, found := a.pathFeatures(ctx, webPath); found {
		t.Error("pathFeatures returned another application's path")
	}
	if _, _, _, _, found := a.pathFeatures(ctx, paymentsPath); !found {
		t.Error("pathFeatures did not return the caller's OWN path")
	}
	if _, found := a.targetCompromise(ctx, webPath); found {
		t.Error("targetCompromise returned another application's target")
	}
}

// The validations board is scoped per record; the aggregates are not, and that is a
// decision rather than a gap - they measure the engine, name nothing, and the same
// numbers are reachable through GraphQL. Asserted so the choice is visible and a future
// change to it is deliberate.
func TestValidationsBoardIsScopedButItsAggregatesAreNot(t *testing.T) {
	a, paymentsPath, webPath := twoAppAPI(t)

	for _, id := range []string{paymentsPath, webPath} {
		if rec := post(t, a.putValidation, unscopedAdmin(), "/validations",
			`{"pathId":"`+id+`","outcome":"confirmed","source":"redteam"}`); rec.Code != http.StatusOK {
			t.Fatalf("seeding a verdict for %s returned %d: %s", id, rec.Code, rec.Body)
		}
	}

	rec := httptest.NewRecorder()
	a.listValidations(rec, httptest.NewRequest(http.MethodGet, "/validations", nil).
		WithContext(scopedAdmin("payments")))
	var got struct {
		Validations []validation.Record `json:"validations"`
		Metrics     *json.RawMessage    `json:"metrics"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Validations) != 1 || got.Validations[0].PathID != paymentsPath {
		t.Errorf("payments-scoped board = %d record(s) %+v, want only its own", len(got.Validations), got.Validations)
	}
	if got.Metrics == nil {
		t.Error("the tenant-wide aggregates were dropped; GraphQL still serves them, so this would be a control in name only")
	}
}
