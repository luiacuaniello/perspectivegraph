package api

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/graphql-go/graphql"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
)

// capRecorder captures audit records so a test can assert a read was logged.
type capRecorder struct{ actions []string }

func (c *capRecorder) Record(action, _, _, _ string, _ map[string]any) {
	c.actions = append(c.actions, action)
}
func (c *capRecorder) has(action string) bool {
	for _, a := range c.actions {
		if a == action {
			return true
		}
	}
	return false
}

func testAPI(t *testing.T) (*API, *capRecorder) {
	t.Helper()
	ctx := context.Background()
	m, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	a := New(m, analyzer.NewService(m, time.Second, nil), nil)
	cap := &capRecorder{}
	a.audit = cap // the tamper-evident reads log (here: capturing) - white-box
	return a, cap
}

func viewerCtx() context.Context {
	return auth.WithPrincipal(context.Background(),
		auth.Principal{Subject: "tester", Role: auth.RoleViewer, Tenant: "default"})
}

// The tool is a map of how to breach the org, so *reads* of the attack paths and
// the exports must land in the audit log - not just writes.
func TestAttackPathsQueryIsAudited(t *testing.T) {
	a, cap := testAPI(t)
	schema, err := a.Schema()
	if err != nil {
		t.Fatal(err)
	}
	res := graphql.Do(graphql.Params{
		Schema:        schema,
		RequestString: "{ attackPaths { id } }",
		Context:       viewerCtx(),
	})
	if len(res.Errors) > 0 {
		t.Fatalf("query errored: %v", res.Errors)
	}
	if !cap.has("view.attack_paths") {
		t.Errorf("viewing attack paths must be audited; got actions %v", cap.actions)
	}
}

func TestExportIsAudited(t *testing.T) {
	a, cap := testAPI(t)

	for _, tc := range []struct {
		name, want string
		h          func(*API) func(rw *httptest.ResponseRecorder)
	}{
		{"ndjson", "export.ndjson", func(api *API) func(*httptest.ResponseRecorder) {
			return func(rw *httptest.ResponseRecorder) {
				api.exportNDJSON(rw, httptest.NewRequest("GET", "/export/ndjson", nil).WithContext(viewerCtx()))
			}
		}},
		{"oscal", "export.oscal", func(api *API) func(*httptest.ResponseRecorder) {
			return func(rw *httptest.ResponseRecorder) {
				api.exportOSCAL(rw, httptest.NewRequest("GET", "/export/oscal", nil).WithContext(viewerCtx()))
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cap.actions = nil
			tc.h(a)(httptest.NewRecorder())
			if !cap.has(tc.want) {
				t.Errorf("export must be audited as %q; got %v", tc.want, cap.actions)
			}
		})
	}
}
