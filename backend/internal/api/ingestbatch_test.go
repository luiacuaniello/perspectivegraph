package api

import (
	"context"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/broker"
)

type fakeBatches map[string]broker.BatchStatus

func (f fakeBatches) BatchStatus(_ context.Context, id string) (broker.BatchStatus, error) {
	return f[id], nil
}

// A batch is visible to the tenant that sent it and to nobody else, and says it is
// complete - with the moment it became so - only once every message landed.
func TestIngestBatchIsScopedToItsTenant(t *testing.T) {
	at := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	a := seededAPI(t).WithIngestBatches(fakeBatches{
		"done": {ID: "done", Tenant: "acme", Messages: 3, Applied: 3, AppliedAt: at},
		"half": {ID: "half", Tenant: "acme", Messages: 3, Applied: 1},
	})
	acme := auth.WithPrincipal(context.Background(), auth.Principal{Subject: "ci", Role: auth.RoleViewer, Tenant: "acme"})
	other := auth.WithPrincipal(context.Background(), auth.Principal{Subject: "ci", Role: auth.RoleViewer, Tenant: "globex"})

	got := query(t, a, `{ ingestBatch(id: "done") { messages applied complete appliedAt } }`, acme)["ingestBatch"].(map[string]any)
	if got["complete"] != true || got["appliedAt"] != at.Format(time.RFC3339Nano) {
		t.Errorf("complete batch = %v", got)
	}
	half := query(t, a, `{ ingestBatch(id: "half") { complete appliedAt } }`, acme)["ingestBatch"].(map[string]any)
	if half["complete"] != false || half["appliedAt"] != nil {
		t.Errorf("half-applied batch = %v; want incomplete, no applied time", half)
	}
	if v := query(t, a, `{ ingestBatch(id: "done") { complete } }`, other)["ingestBatch"]; v != nil {
		t.Errorf("another tenant saw the batch: %v", v)
	}
	if v := query(t, a, `{ ingestBatch(id: "nope") { complete } }`, acme)["ingestBatch"]; v != nil {
		t.Errorf("an unknown batch answered %v, want null", v)
	}
}

// Reading as a tenant nobody has written must not create it: the reader sees an empty
// graph, and the engine gains no graph, no store and no analyzer loop for it.
func TestReadingAnUnknownTenantCreatesNothing(t *testing.T) {
	a := seededAPI(t)
	before := a.manager.Tenants()
	stranger := auth.WithPrincipal(context.Background(), auth.Principal{Subject: "sso:new", Role: auth.RoleViewer, Tenant: "never-configured"})
	got := query(t, a, `{ graph { nodes { id } } attackPaths { id } }`, stranger)
	if nodes := got["graph"].(map[string]any)["nodes"].([]any); len(nodes) != 0 {
		t.Errorf("an unknown tenant sees %d nodes, want none", len(nodes))
	}
	if after := a.manager.Tenants(); len(after) != len(before) {
		t.Errorf("tenants %v became %v: a read created one", before, after)
	}

	// And through HTTP, where reads go through the per-request snapshot loader.
	a.WithAuth(auth.NewTokenStore("t0k3n:viewer:never_configured_http"), nil)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	res := postGraphQL(t, h, `{ graph { nodes { id } } }`, "Authorization", "Bearer t0k3n")
	if len(res.Errors) > 0 || len(res.Data["graph"].(map[string]any)["nodes"].([]any)) != 0 {
		t.Errorf("HTTP read as an unknown tenant: %+v", res)
	}
	if after := a.manager.Tenants(); len(after) != len(before) {
		t.Errorf("tenants %v became %v: an HTTP read created one", before, after)
	}
}
