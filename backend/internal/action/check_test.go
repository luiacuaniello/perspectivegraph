package action

import (
	"context"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type fakeStatus struct {
	calls []string // "slug@sha=state"
	links []string // the target URL of each call, in order
}

func (f *fakeStatus) forge() string { return "github" }
func (f *fakeStatus) enabled() bool { return true }
func (f *fakeStatus) postStatus(_ context.Context, slug, sha, state, _, link string) error {
	f.calls = append(f.calls, slug+"@"+sha+"="+state)
	f.links = append(f.links, link)
	return nil
}

// pathWithPR builds a path whose entry node carries PR commit context.
func pathWithPR(slug, sha, jewel string) analyzer.AttackPath {
	return analyzer.AttackPath{Nodes: []ontology.Node{
		{ID: "lb", Properties: map[string]any{ontology.PropRepoSlug: slug, ontology.PropCommitSHA: sha}},
		{ID: "jewel", Name: jewel, Properties: map[string]any{ontology.PropCrownJewel: true}},
	}}
}

// TestCheckFailsThenResolves: a PR on a critical path goes red; when the next
// pass no longer has it, the same commit flips green.
func TestCheckFailsThenResolves(t *testing.T) {
	fp := &fakeStatus{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "")
	ctx := context.Background()

	// Pass 1: the PR's change sits on a critical path → failure.
	r.OnCriticalPaths(ctx, "default", []analyzer.AttackPath{pathWithPR("acme/web", "deadbeef", "customers-db")})
	if len(fp.calls) != 1 || fp.calls[0] != "acme/web@deadbeef=failure" {
		t.Fatalf("expected one failure status, got %v", fp.calls)
	}

	// Pass 2: path gone (fixed) → the same commit flips to success.
	r.OnCriticalPaths(ctx, "default", nil)
	if len(fp.calls) != 2 || fp.calls[1] != "acme/web@deadbeef=success" {
		t.Fatalf("expected a success status on resolution, got %v", fp.calls)
	}
}

// TestCheckSkipsPathsWithoutCommit: no commit SHA → nothing to attach a status to.
func TestCheckSkipsPathsWithoutCommit(t *testing.T) {
	fp := &fakeStatus{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "")
	// PR slug but no commit sha.
	p := analyzer.AttackPath{Nodes: []ontology.Node{
		{ID: "lb", Properties: map[string]any{ontology.PropRepoSlug: "acme/web"}},
		{ID: "j", Properties: map[string]any{ontology.PropCrownJewel: true}},
	}}
	r.OnCriticalPaths(context.Background(), "default", []analyzer.AttackPath{p})
	if len(fp.calls) != 0 {
		t.Errorf("a path without a commit sha must not post a status, got %v", fp.calls)
	}
}

// The "Details" link of a status opens that commit's verdict page, red and green alike: the
// dashboard's front page left a developer to find their change among every route in the
// estate. Without a dashboard there is no link at all.
func TestStatusLinksToTheCommitsVerdict(t *testing.T) {
	fp := &fakeStatus{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "https://pg.example.com/")
	ctx := context.Background()
	r.OnCriticalPaths(ctx, "default", []analyzer.AttackPath{pathWithPR("acme/web", "deadbeef", "customers-db")})
	r.OnCriticalPaths(ctx, "default", nil)
	want := "https://pg.example.com/#verdict/acme/web/deadbeef"
	if len(fp.links) != 2 || fp.links[0] != want || fp.links[1] != want {
		t.Fatalf("links = %q, want %q on the failure and on the success", fp.links, want)
	}

	none := &fakeStatus{}
	newStatusReporter(none, mustAllow(t, "acme/*"), "").OnCriticalPaths(ctx, "default",
		[]analyzer.AttackPath{pathWithPR("acme/web", "deadbeef", "customers-db")})
	if len(none.links) != 1 || none.links[0] != "" {
		t.Errorf("without a dashboard the status must carry no link, got %q", none.links)
	}
}

// The slug and the SHA come from ingested data. Whatever they hold stays inside its own
// segment of the link: it cannot end the fragment, add a query or climb out of the page.
func TestVerdictLinkEscapesEachSegment(t *testing.T) {
	cases := map[string]struct{ dashboard, slug, sha, want string }{
		"plain":            {"https://pg.example.com", "acme/web", "3f2a91c", "https://pg.example.com/#verdict/acme/web/3f2a91c"},
		"a path, a slash":  {"https://example.com/pg/", "acme/web", "3f2a91c", "https://example.com/pg/#verdict/acme/web/3f2a91c"},
		"its own fragment": {"https://pg.example.com/#today", "acme/web", "3f2a91c", "https://pg.example.com/#verdict/acme/web/3f2a91c"},
		"subgroups":        {"https://pg.example.com", "group/sub/project", "3f2a91c", "https://pg.example.com/#verdict/group/sub/project/3f2a91c"},
		"a hostile SHA":    {"https://pg.example.com", "acme/web", "abc?x=1#y/../z", "https://pg.example.com/#verdict/acme/web/abc%3Fx=1%23y%2F..%2Fz"},
		"no dashboard":     {"", "acme/web", "3f2a91c", ""},
	}
	for name, c := range cases {
		if got := verdictLink(c.dashboard, c.slug, c.sha); got != c.want {
			t.Errorf("%s: verdictLink = %q, want %q", name, got, c.want)
		}
	}
}
