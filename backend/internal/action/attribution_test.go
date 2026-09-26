package action

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// statusLog records every status posted, with its description.
type statusLog struct{ calls, descs []string }

func (f *statusLog) forge() string { return "github" }
func (f *statusLog) enabled() bool { return true }
func (f *statusLog) postStatus(_ context.Context, slug, sha, state, desc, _ string) error {
	f.calls = append(f.calls, slug+"@"+sha+"="+state)
	f.descs = append(f.descs, desc)
	return nil
}

func stampOf(slug, sha string) map[string]any {
	return map[string]any{ontology.PropRepoSlug: slug, ontology.PropCommitSHA: sha, ontology.PropPRNumber: 7}
}

// route is an entry-to-asset path through the given stamped assets.
func route(id, from, to string, score float64, via ...ontology.Node) analyzer.AttackPath {
	nodes := append([]ontology.Node{{ID: from, Name: from}}, via...)
	nodes = append(nodes, ontology.Node{ID: to, Name: to, Properties: map[string]any{ontology.PropCrownJewel: true}})
	return analyzer.AttackPath{ID: id, Score: score, Nodes: nodes}
}

// arrives shows the ledger the estate before a commit, then the pass it arrives in.
func arrives(l *impact.Ledger, tenant string, before []analyzer.AttackPath, img ontology.Node, after []analyzer.AttackPath) {
	l.ObservePass(tenant, graph.Snapshot{}, before)
	l.ObservePass(tenant, graph.Snapshot{Nodes: []ontology.Node{img}}, after)
}

// The engine's commit status follows the merge gate: a commit that only touches a route
// that was already there stays out of it, and one that opens a route goes red - once, not
// on every pass - and back to green when that route closes.
func TestTheStatusCountsWhatTheChangeOpened(t *testing.T) {
	ledger := impact.NewLedger()
	fp := &statusLog{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "")
	r.judge = ledger
	ctx := context.Background()

	// c1 only touches a route that was there.
	img := ontology.Node{ID: "img", Properties: stampOf("acme/web", "c1")}
	old := route("p-old", "lb", "db", 0.5, img)
	arrives(ledger, "t", []analyzer.AttackPath{route("p-old", "lb", "db", 0.5)}, img, []analyzer.AttackPath{old})
	r.OnCriticalPaths(ctx, "t", []analyzer.AttackPath{old})
	if len(fp.calls) != 0 {
		t.Fatalf("a commit on a route that was already there got %v", fp.calls)
	}

	// c2 arrives with a route of its own, through the same route's assets as well.
	api := ontology.Node{ID: "api", Properties: stampOf("acme/api", "c2")}
	old2 := route("p-old", "lb", "db", 0.5, api)
	opened := route("p-new", "lb2", "vault", 0.7, api)
	ledger.ObservePass("t", graph.Snapshot{Nodes: []ontology.Node{img, api}}, []analyzer.AttackPath{old2, opened})
	r.OnCriticalPaths(ctx, "t", []analyzer.AttackPath{old2, opened})
	r.OnCriticalPaths(ctx, "t", []analyzer.AttackPath{old2, opened}) // unchanged: not posted again
	if len(fp.calls) != 1 || fp.calls[0] != "acme/api@c2=failure" {
		t.Fatalf("calls = %v, want one failure, on c2", fp.calls)
	}
	if want := "1 critical attack path(s) opened or made likelier by this change (1 already there)"; fp.descs[0] != want {
		t.Errorf("description = %q, want %q", fp.descs[0], want)
	}

	ledger.ObservePass("t", graph.Snapshot{Nodes: []ontology.Node{img, api}}, []analyzer.AttackPath{old2})
	r.OnCriticalPaths(ctx, "t", []analyzer.AttackPath{old2})
	if len(fp.calls) != 2 || fp.calls[1] != "acme/api@c2=success" {
		t.Fatalf("calls = %v, want the failure cleared", fp.calls)
	}
	if want := "No critical attack path opened by this change (1 already there pass through it)"; fp.descs[1] != want {
		t.Errorf("description = %q, want %q", fp.descs[1], want)
	}
}

// A route that appears through a commit after it arrived, with no pull request arriving
// on it, counts - and the status does not claim the change opened it.
func TestARouteThatAppearedLaterSaysSo(t *testing.T) {
	ledger := impact.NewLedger()
	fp := &statusLog{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "")
	r.judge = ledger
	img := ontology.Node{ID: "img", Properties: stampOf("acme/web", "c1")}
	arrives(ledger, "t", nil, img, nil)
	late := route("p", "lb", "db", 0.5, img)
	ledger.ObservePass("t", graph.Snapshot{Nodes: []ontology.Node{img}}, []analyzer.AttackPath{late})
	r.OnCriticalPaths(context.Background(), "t", []analyzer.AttackPath{late})
	if len(fp.calls) != 1 || fp.descs[0] != "1 critical attack path(s) opened or made likelier since this change arrived" {
		t.Fatalf("calls = %v %q", fp.calls, fp.descs)
	}
}

// PR_ATTRIBUTION=commit is the rule before 1.22, words included: every route through the
// commit counts.
func TestTheCommitRuleKeepsItsWords(t *testing.T) {
	fp := &statusLog{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "") // no ledger
	img := ontology.Node{ID: "img", Properties: stampOf("acme/web", "c1")}
	r.OnCriticalPaths(context.Background(), "t", []analyzer.AttackPath{route("p", "lb", "db", 0.5, img)})
	r.OnCriticalPaths(context.Background(), "t", nil)
	want := []string{"1 critical attack path(s) reach a sensitive asset from this change", "No critical attack path from this change"}
	if strings.Join(fp.descs, "|") != strings.Join(want, "|") {
		t.Fatalf("descriptions = %q, want %q", fp.descs, want)
	}
}

// A commit the ledger never saw arrive - it was in the graph when the engine started - is
// judged by the per-commit rule, and the status says so.
func TestACommitFromBeforeTheEngineWatchedIsJudgedPerCommit(t *testing.T) {
	ledger := impact.NewLedger()
	fp := &statusLog{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "")
	r.judge = ledger
	img := ontology.Node{ID: "img", Properties: stampOf("acme/web", "c1")}
	paths := []analyzer.AttackPath{route("p", "lb", "db", 0.5, img)}
	ledger.ObservePass("t", graph.Snapshot{Nodes: []ontology.Node{img}}, paths) // first pass: already there
	r.OnCriticalPaths(context.Background(), "t", paths)
	if len(fp.calls) != 1 || !strings.Contains(fp.descs[0], "before the engine was watching") {
		t.Fatalf("calls = %v %q, want a failure that says why", fp.calls, fp.descs)
	}
}

// Each tenant's pass judges its own commits. The reporter's state used to be shared, so
// a pass of one tenant - which does not see the other's routes - posted `success` on the
// other tenant's red commits: a merge gate opened by an unrelated estate.
func TestAPassOfOneTenantDoesNotClearAnother(t *testing.T) {
	fp := &statusLog{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "")
	img := ontology.Node{ID: "img", Properties: stampOf("acme/web", "c1")}
	r.OnCriticalPaths(context.Background(), "a", []analyzer.AttackPath{route("p", "lb", "db", 0.5, img)})
	r.OnCriticalPaths(context.Background(), "b", nil)
	if len(fp.calls) != 1 {
		t.Fatalf("calls = %v, want only tenant a's failure", fp.calls)
	}
	r.OnCriticalPaths(context.Background(), "a", nil)
	if len(fp.calls) != 2 || fp.calls[1] != "acme/web@c1=success" {
		t.Fatalf("calls = %v, want tenant a's own pass to clear it", fp.calls)
	}
}

// A route through two changes is a question for each. Only the first commit on a path
// used to be judged: under the per-commit rule the second change on a route never went
// red, and under the gate's rule the route the second change opened - through an asset
// of the first - would have blocked neither.
func TestEveryCommitOnAPathIsJudged(t *testing.T) {
	img := ontology.Node{ID: "img", Properties: stampOf("acme/web", "c1")}
	deploy := ontology.Node{ID: "deploy", Properties: stampOf("acme/infra", "c2")}
	through := route("p", "lb", "db", 0.5, img, deploy)

	// Per commit: both.
	fp := &statusLog{}
	newStatusReporter(fp, mustAllow(t, "acme/*"), "").OnCriticalPaths(context.Background(), "t", []analyzer.AttackPath{through})
	slices.Sort(fp.calls)
	if got := strings.Join(fp.calls, " "); got != "acme/infra@c2=failure acme/web@c1=failure" {
		t.Fatalf("per commit: calls = %q, want both red", got)
	}

	// The gate's rule: c1 arrived first, on no route; c2 arrives and opens one through
	// c1's image. It is c2's.
	ledger := impact.NewLedger()
	fp = &statusLog{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "")
	r.judge = ledger
	arrives(ledger, "t", nil, img, nil)
	ledger.ObservePass("t", graph.Snapshot{Nodes: []ontology.Node{img, deploy}}, []analyzer.AttackPath{through})
	r.OnCriticalPaths(context.Background(), "t", []analyzer.AttackPath{through})
	if got := strings.Join(fp.calls, " "); got != "acme/infra@c2=failure" {
		t.Fatalf("diff: calls = %q, want only the change that opened it", got)
	}
}

// The comments follow the same rule: none on a route the change found there, and one on
// a route it made likelier that says so, with both figures.
func TestTheCommentsFollowTheGate(t *testing.T) {
	mock := &mockGH{}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	ledger := impact.NewLedger()
	c := NewGitHubCommenter(GitHubConfig{Token: "t", BaseURL: srv.URL, Allow: mustAllow(t, "acme/*"), Attribution: ledger})
	img := ontology.Node{ID: "img", Name: "app:1.0", Properties: stampOf("acme/web", "c1")}
	old := route("p-old", "lb", "db", 0.5, img)
	arrives(ledger, "t", []analyzer.AttackPath{route("p-old", "lb", "db", 0.5)}, img, []analyzer.AttackPath{old})
	c.OnCriticalPaths(context.Background(), "t", []analyzer.AttackPath{old})
	if mock.posts != 0 || mock.gets != 0 {
		t.Fatalf("commented on a route the change found there: posts=%d gets=%d", mock.posts, mock.gets)
	}

	lib := ontology.Node{ID: "lib", Name: "lib", Properties: stampOf("acme/api", "c2")}
	worse := route("p-old", "lb", "db", 0.8, img, lib)
	ledger.ObservePass("t", graph.Snapshot{Nodes: []ontology.Node{img, lib}}, []analyzer.AttackPath{worse})
	c.OnCriticalPaths(context.Background(), "t", []analyzer.AttackPath{worse})
	if mock.posts != 1 || !strings.Contains(mock.comments[0].Body, "This change makes it likelier:** 50% before it, 80% now") {
		t.Fatalf("posts=%d comments=%+v, want one comment saying the route got likelier", mock.posts, mock.comments)
	}
}
