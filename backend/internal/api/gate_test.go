package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// fixture stands in for a scanner: whatever the body, it reports the events given, stamped
// with the request's commit the way the real collectors stamp theirs.
type fixture struct{ events []ontology.Event }

func (fixture) Source() string { return "fixture" }

func (f fixture) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	_, _ = io.Copy(io.Discard, r)
	out := make([]ontology.Event, len(f.events))
	for i, ev := range f.events {
		ev.Nodes = append([]ontology.Node(nil), ev.Nodes...)
		for j := range ev.Nodes {
			ev.Nodes[j].Properties = graph.MergeProps(ev.Nodes[j].Properties, opts.PRProps())
		}
		out[i] = ev
	}
	return out, nil
}

// gateAPI is the seeded estate (edge-alb → payments → payments-admin) with the gate
// enabled on a fixture scanner, and a credential to call it with.
func gateAPI(t *testing.T, change ...ontology.Event) *API {
	t.Helper()
	a := seededAPI(t).WithGate([]ingestion.Collector{fixture{events: change}}, nil)
	return a.WithAuth(auth.NewTokenStore("gate:viewer,scoped:viewer::2099-01-01:billing-api"), nil)
}

func postGate(t *testing.T, a *API, token, query string) (int, gateImpact) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/gate/impact?"+query, strings.NewReader(`{"report":"x"}`))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := serve(t, a, r)
	var out gateImpact
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

const gateQuery = "source=fixture&slug=acme/payments&sha=c0ffee"

// payments is rescanned and now also reaches a sensitive bucket nothing reached before.
func reachesLedger() ontology.Event {
	return ontology.Event{Source: "fixture", Kind: ontology.KindFinding,
		Nodes: []ontology.Node{
			{ID: "svc", Label: ontology.LabelContainer, Name: "payments", Properties: map[string]any{"app": "payments-api"}},
			{ID: "ledger", Label: ontology.LabelBucket, Name: "ledger", Properties: map[string]any{ontology.PropCrownJewel: true, "app": "payments-api"}},
		},
		Edges: []ontology.Edge{{Type: ontology.EdgeHasPermission, From: "svc", To: "ledger", ExploitProbability: 0.7}},
	}
}

func TestTheGateCountsTheRoutesAChangeOpens(t *testing.T) {
	a := gateAPI(t, reachesLedger())
	code, v := postGate(t, a, "gate", gateQuery)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if v.Attribution != "diff" || !v.Analysed || !v.Reachable {
		t.Fatalf("attribution=%q analysed=%v reachable=%v", v.Attribution, v.Analysed, v.Reachable)
	}
	if v.CriticalPaths != 1 || v.Paths[0].Change != "introduced" || v.Paths[0].Nodes[len(v.Paths[0].Nodes)-1].Name != "ledger" {
		t.Fatalf("paths = %+v, want the one new route to the ledger", v.Paths)
	}
	// The route to payments-admin runs through the rescanned container but was there
	// before: the per-commit rule counted it, the comparison does not.
	if v.Preexisting != 1 {
		t.Errorf("preexisting = %d, want the route to payments-admin", v.Preexisting)
	}
}

// A dry run: the report is never written into the live graph.
func TestTheGateWritesNothing(t *testing.T) {
	a := gateAPI(t, reachesLedger())
	store, err := a.manager.For(context.Background(), graph.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Snapshot(context.Background())
	if code, _ := postGate(t, a, "gate", gateQuery); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	after, _ := store.Snapshot(context.Background())
	if len(after.Nodes) != len(before.Nodes) || len(after.Edges) != len(before.Edges) {
		t.Fatalf("the live graph changed: %d/%d nodes, %d/%d edges", len(before.Nodes), len(after.Nodes), len(before.Edges), len(after.Edges))
	}
	for _, n := range after.Nodes {
		if ontology.StampedWith(n.Properties, "acme/payments", "c0ffee") {
			t.Errorf("node %s in the live graph carries the commit", n.ID)
		}
	}
}

// A caller scoped to other applications still gets the right count - leaving the route
// out would answer clean - but not the names of assets it may not read.
func TestTheGateRedactsRoutesOutsideTheCallersApplications(t *testing.T) {
	a := gateAPI(t, reachesLedger())
	code, v := postGate(t, a, "scoped", gateQuery)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if v.CriticalPaths != 1 || !v.Paths[0].Redacted || len(v.Paths[0].Nodes) != 0 || v.Paths[0].ID != "" {
		t.Errorf("paths = %+v, want one counted, unnamed route", v.Paths)
	}
}

func TestTheGateRefusesAnonymousAndMalformedCalls(t *testing.T) {
	anon, err := auth.NewAnonymous(auth.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	public := seededAPI(t).WithGate([]ingestion.Collector{fixture{events: []ontology.Event{reachesLedger()}}}, nil).
		WithAuth(auth.Chain{auth.NewTokenStore("gate:viewer"), anon}, nil)
	if code, _ := postGate(t, public, "", gateQuery); code != http.StatusForbidden {
		t.Errorf("anonymous caller on a public instance: status %d, want 403", code)
	}
	if code, _ := postGate(t, public, "gate", gateQuery); code != http.StatusOK {
		t.Errorf("signed-in caller on a public instance: status %d, want 200", code)
	}
	a := gateAPI(t, reachesLedger())
	if code, _ := postGate(t, a, "", gateQuery); code != http.StatusUnauthorized {
		t.Errorf("no credential: status %d, want 401", code)
	}
	if code, _ := postGate(t, a, "gate", "source=nope&slug=acme/payments&sha=c0ffee"); code != http.StatusNotFound {
		t.Errorf("unknown collector: status %d, want 404", code)
	}
	if code, _ := postGate(t, a, "gate", "source=fixture&slug=acme/payments"); code != http.StatusBadRequest {
		t.Errorf("no sha: status %d, want 400", code)
	}
	if code, _ := postGate(t, seededAPI(t).WithAuth(auth.NewTokenStore("gate:viewer"), nil), "gate", gateQuery); code != http.StatusNotFound {
		t.Errorf("gate not enabled: status %d, want 404", code)
	}
}
