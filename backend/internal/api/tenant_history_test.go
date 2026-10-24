package api

import (
	"context"
	"testing"

	"github.com/graphql-go/graphql"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
)

// The analyzer records the history under the tenant the graph keys it by, normalized:
// "Acme-Corp" in a token is "acme_corp" there. The API used to read it back under the
// token's own spelling, so a tenant named anything but lower-case letters, digits and
// underscores saw no trend, no MTTR and no path ages, however long it had been watched.
func TestATenantReadsTheHistoryTheAnalyzerWroteForIt(t *testing.T) {
	a, _ := testAPI(t)
	h, err := history.New("")
	if err != nil {
		t.Fatal(err)
	}
	a.WithHistory(h)
	h.ObservePass(graph.NormalizeTenant("Acme-Corp"), []history.Observation{{ID: "ap-1", Route: "web → db", Score: 0.9}}, 42)

	schema, err := a.Schema()
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{Subject: "sso:a", Role: auth.RoleViewer, Tenant: "Acme-Corp"})
	res := graphql.Do(graphql.Params{Schema: schema, Context: ctx,
		RequestString: "{ history { trend { criticalPaths riskPct } } }"})
	if len(res.Errors) > 0 {
		t.Fatalf("query errored: %v", res.Errors)
	}
	trend, _ := res.Data.(map[string]any)["history"].(map[string]any)["trend"].([]any)
	if len(trend) == 0 {
		t.Fatalf("Acme-Corp sees no trend, though the analyzer recorded a pass for it: %v", res.Data)
	}
}
