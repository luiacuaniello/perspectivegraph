package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
)

// bypasses lists, as file:line, every place in src where a resolver takes a tenant or an
// application list from somewhere other than view: from the request context, from the
// API's own reads (kept for the REST handlers) or from a store read directly.
func bypasses(t *testing.T, name, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	direct := map[string]bool{"tenantOf": true, "graphTenantOf": true, "allowedApps": true}
	apiReads := map[string]bool{"snapshot": true, "rawSnapshot": true, "scopedLatest": true, "shownPaths": true, "scopedPathIDs": true, "mayActOnPath": true}
	stores := map[string]bool{"suppress": true, "ticket": true, "validation": true, "history": true, "analyzer": true, "coverage": true, "search": true, "batches": true}
	var found []string
	at := func(n ast.Node, what string) {
		found = append(found, fset.Position(n.Pos()).String()+": "+what)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && direct[id.Name] {
				at(x, id.Name)
			}
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case id.Name == "auth" && x.Sel.Name == "PrincipalFromContext":
				at(x, "auth.PrincipalFromContext")
			case id.Name == "a" && (apiReads[x.Sel.Name] || stores[x.Sel.Name]):
				at(x, "a."+x.Sel.Name)
			}
		}
		return true
	})
	return found
}

// The resolvers read through view, and only through it: which spelling of the tenant each
// store is keyed by, and what an app-scoped caller may see, is decided in scope.go once. A
// resolver that asks the request context for the tenant, or reads a store directly, picks
// for itself - which is how two resolvers came to read search and history under the wrong
// spelling of the tenant, and find nothing.
func TestResolversReadThroughTheView(t *testing.T) {
	files, err := filepath.Glob("schema*.go")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) // #nosec G304 -- a glob of this package's own files
		if err != nil {
			t.Fatal(err)
		}
		found = append(found, bypasses(t, name, string(src))...)
		checked++
	}
	if checked < 5 {
		t.Fatalf("checked %d schema files; the glob no longer finds them", checked)
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("%s: read through a.view(ctx) instead", f)
	}

	// The check finds what it is there to find.
	planted := `package api
func (a *API) x(p graphql.ResolveParams) {
	_ = tenantOf(p.Context)
	_, _ = a.snapshot(p.Context)
	_, _, _ = a.suppress.Get(p.Context, "t", "id")
	_ = auth.PrincipalFromContext(p.Context)
	_ = a.view(p.Context).latest()
}`
	if got := bypasses(t, "planted.go", planted); len(got) != 4 {
		t.Errorf("the check found %d of the 4 planted bypasses: %v", len(got), got)
	}
}

// The cached risk simulation names the crown jewels it measures. A caller limited to one
// application used to get every jewel of the tenant from it - another team's database by
// name - while the same query given arguments of its own simulated the caller's graph
// alone. The aggregates measure the tenant and name nothing, so they stay as they are.
func TestTheCachedRiskSimulationNamesOnlyTheCallersJewels(t *testing.T) {
	a, _, _ := twoAppAPI(t)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(a.analyzer.LatestRisk(auth.DefaultTenant).CrownJewels) < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	all := a.analyzer.LatestRisk(auth.DefaultTenant)
	if len(all.CrownJewels) != 2 {
		t.Fatalf("the cached simulation has %d crown jewels, want both applications' 2", len(all.CrownJewels))
	}

	const q = `{ riskSimulation { anyCompromiseProbability crownJewels { id } } }`
	jewels := func(data map[string]any) (ids []string, prob float64) {
		risk, _ := data["riskSimulation"].(map[string]any)
		prob, _ = risk["anyCompromiseProbability"].(float64)
		list, _ := risk["crownJewels"].([]any)
		for _, j := range list {
			m, _ := j.(map[string]any)
			id, _ := m["id"].(string)
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return ids, prob
	}

	ids, scopedAny := jewels(query(t, a, q, scopedAdmin("payments")))
	if strings.Join(ids, ",") != "db-payments" {
		t.Errorf("the payments-scoped caller sees jewels %v, want only db-payments", ids)
	}
	ids, unscopedAny := jewels(query(t, a, q, unscopedAdmin()))
	if strings.Join(ids, ",") != "db-payments,db-web" {
		t.Errorf("an unrestricted caller sees jewels %v, want both", ids)
	}
	if scopedAny != unscopedAny {
		t.Errorf("anyCompromiseProbability = %v scoped, %v unscoped: the aggregate is the tenant's for every caller", scopedAny, unscopedAny)
	}
	if n := len(a.analyzer.LatestRisk(auth.DefaultTenant).CrownJewels); n != 2 {
		t.Errorf("filtering one caller's view left the shared cache with %d jewels, want 2", n)
	}
}
