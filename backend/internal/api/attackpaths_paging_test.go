package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// estateAPI builds an API over the estate `build` describes and waits until the analyzer
// has ranked `routes` of its routes. seededAPI's estate has one route, which cannot show
// whether a page is the right page or whether an alternate route is treated as one.
func estateAPI(t *testing.T, routes int, build func(node func(ontology.Node), exposes func(from, to string, p float64))) *API {
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
	build(
		func(n ontology.Node) { must(store.UpsertNode(ctx, n)) },
		func(from, to string, p float64) {
			must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: from, To: to, ExploitProbability: p}))
		},
	)

	runCtx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	svc := analyzer.NewService(mgr, 5*time.Millisecond, nil)
	go func() { _ = svc.Run(runCtx) }()
	deadline := time.Now().Add(10 * time.Second)
	for len(svc.Latest(graph.DefaultTenant)) < routes {
		if time.Now().After(deadline) {
			t.Fatalf("analyzer ranked %d of the %d routes within 10s", len(svc.Latest(graph.DefaultTenant)), routes)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return New(mgr, svc, nil)
}

// fanInAPI is n internet-facing load balancers in front of one container, which reaches an
// admin role: n routes to one target. The first belongs to another application, so paging
// has a scope to respect.
func fanInAPI(t *testing.T, n int) *API {
	t.Helper()
	return estateAPI(t, n, func(node func(ontology.Node), exposes func(from, to string, p float64)) {
		node(ontology.Node{ID: "svc", Label: ontology.LabelContainer, Name: "payments"})
		node(ontology.Node{ID: "role", Label: ontology.LabelIAMRole, Name: "payments-admin",
			Properties: map[string]any{ontology.PropCrownJewel: true}})
		exposes("svc", "role", 0.8)
		for i := range n {
			app := "payments-api"
			if i == 0 {
				app = "edge-team"
			}
			id := fmt.Sprintf("lb%d", i)
			node(ontology.Node{ID: id, Label: ontology.LabelLoadBalancer, Name: "alb-" + id,
				Properties: map[string]any{ontology.PropInternetExposed: true, "app": app}})
			// A different probability on each, so the ranking has one order and a page
			// has one right answer.
			exposes(id, "svc", 0.9-0.1*float64(i))
		}
	})
}

func pathIDs(t *testing.T, a *API, args string) []string {
	t.Helper()
	q := "{ attackPaths { id } }"
	if args != "" {
		q = "{ attackPaths(" + args + ") { id } }"
	}
	rows, _ := query(t, a, q)["attackPaths"].([]any)
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		id, _ := r.(map[string]any)["id"].(string)
		ids = append(ids, id)
	}
	return ids
}

// limit alone gives a caller the top of the ranking and no way to the rest of it: with a
// hundred routes and a limit of twenty, eighty were out of reach of anything that pages.
// offset has to be a window on the same ranking limit cuts - same order, no route twice,
// none skipped.
func TestAttackPathsOffsetPagesTheRanking(t *testing.T) {
	a := fanInAPI(t, 5)
	all := pathIDs(t, a, "")
	if len(all) != 5 {
		t.Fatalf("the estate has %d routes, want 5", len(all))
	}

	var paged []string
	for offset := 0; offset < len(all); offset += 2 {
		page := pathIDs(t, a, fmt.Sprintf("limit: 2, offset: %d", offset))
		if len(page) > 2 {
			t.Fatalf("offset %d: %d routes on a page of 2", offset, len(page))
		}
		paged = append(paged, page...)
	}
	if fmt.Sprint(paged) != fmt.Sprint(all) {
		t.Errorf("paging two at a time returned\n  %v\nwant the ranking in order, each route once:\n  %v", paged, all)
	}

	if got := pathIDs(t, a, "offset: 3"); fmt.Sprint(got) != fmt.Sprint(all[3:]) {
		t.Errorf("offset without a limit returned %v, want the rest of the ranking %v", got, all[3:])
	}
	// A caller that pages until a short page must be able to ask for one page too many.
	for _, args := range []string{"offset: 5", "limit: 2, offset: 99"} {
		if got := pathIDs(t, a, args); len(got) != 0 {
			t.Errorf("attackPaths(%s) past the end returned %v, want an empty list", args, got)
		}
	}
	// A negative offset is a caller's mistake, not a request for the end of the list.
	if got := pathIDs(t, a, "limit: 2, offset: -1"); fmt.Sprint(got) != fmt.Sprint(all[:2]) {
		t.Errorf("a negative offset returned %v, want the first page %v", got, all[:2])
	}
}

// The window is on the scoped ranking. Applied before the scope, offset would skip routes
// of other applications: a page of an application's routes would come back short, or
// empty, while the application still had routes to show.
func TestAttackPathsOffsetCountsWithinTheApplication(t *testing.T) {
	a := fanInAPI(t, 5) // lb0 is edge-team's; lb1..lb4 are payments-api's
	scoped := pathIDs(t, a, `app: "payments-api"`)
	if len(scoped) != 4 {
		t.Fatalf("payments-api has %d routes, want 4", len(scoped))
	}
	got := pathIDs(t, a, `app: "payments-api", limit: 2, offset: 2`)
	if fmt.Sprint(got) != fmt.Sprint(scoped[2:4]) {
		t.Errorf("the second page of payments-api's routes is %v, want %v", got, scoped[2:4])
	}
}
