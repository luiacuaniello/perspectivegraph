package action

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func mustAllow(t *testing.T, patterns ...string) *RepoAllow {
	t.Helper()
	a, err := NewRepoAllow(patterns)
	if err != nil {
		t.Fatalf("NewRepoAllow(%v): %v", patterns, err)
	}
	return a
}

func TestValidSlug(t *testing.T) {
	for _, s := range []string{
		"acme/web", "acme/payments-api", "a/b", "Acme/Web.js", "group/subgroup/project",
	} {
		if !ValidSlug(s) {
			t.Errorf("ValidSlug(%q) = false, want true", s)
		}
	}
	// The dot-segment and separator cases are the ones that matter: the GitHub calls
	// interpolate the slug into a URL path, so a slug that can carry ".." or a query
	// is a slug that can address a different endpoint.
	for _, s := range []string{
		"", "acme", "acme/", "/web", "acme//web", "../../user/repos", "acme/..",
		"acme/./web", "acme/web?x=1", "acme/web#frag", "acme/we b", "acme/w%2Fb",
		"a/b/c/d/e", "acme/" + string(make([]byte, 101)),
	} {
		if ValidSlug(s) {
			t.Errorf("ValidSlug(%q) = true, want false", s)
		}
	}
}

func TestRepoAllowPermit(t *testing.T) {
	a := mustAllow(t, "acme/web", "widgets/*")
	for _, s := range []string{"acme/web", "ACME/Web", "widgets/anything", "widgets/x.y"} {
		if !a.Permit(s) {
			t.Errorf("Permit(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"acme/other", "attacker/repo", "acme/web/extra", "acme/../widgets/x"} {
		if a.Permit(s) {
			t.Errorf("Permit(%q) = true, want false", s)
		}
	}
}

// The guard has to fail closed. A call site that forgets to pass an allowlist, or an
// operator who enables a forge token without configuring one, must write nowhere -
// the alternative is what this guard exists to stop: writing wherever the graph points.
func TestNilAndEmptyRepoAllowDenyEverything(t *testing.T) {
	var nilAllow *RepoAllow
	if nilAllow.Permit("acme/web") {
		t.Error("nil *RepoAllow permitted a write")
	}
	if nilAllow.Configured() {
		t.Error("nil *RepoAllow reported itself configured")
	}
	empty := mustAllow(t)
	if empty.Permit("acme/web") {
		t.Error("empty allowlist permitted a write")
	}
	if empty.Configured() {
		t.Error("empty allowlist reported itself configured")
	}
}

func TestNewRepoAllowRejectsBadPatterns(t *testing.T) {
	for _, p := range []string{"acme", "*", "*/*", "../*", "acme/we b", "a/b/*"} {
		if _, err := NewRepoAllow([]string{p}); err == nil {
			t.Errorf("NewRepoAllow(%q) accepted an invalid pattern", p)
		}
	}
}

// ── the vulnerability these tests exist for ──────────────────────────
//
// The slug is a NODE PROPERTY, so it comes from the ingest path - a scanner's HMAC key
// is the least-trusted credential in the deployment. Before the allowlist, planting one
// node was enough to make the engine write to a repository the operator never named,
// with the operator's token. A commit status is the sharp end: a `success` on a commit
// in a repository where this check is required opens a merge gate.

func pathToRepo(slug string) analyzer.AttackPath {
	return analyzer.AttackPath{Nodes: []ontology.Node{
		{ID: "lb", Properties: map[string]any{
			ontology.PropRepoSlug:  slug,
			ontology.PropCommitSHA: "deadbeef",
			ontology.PropPRNumber:  7,
		}},
		{ID: "jewel", Name: "customers-db", Properties: map[string]any{ontology.PropCrownJewel: true}},
	}}
}

func TestCheckerRefusesRepoOutsideAllowlist(t *testing.T) {
	fp := &fakeStatus{}
	r := newStatusReporter(fp, mustAllow(t, "acme/*"), "")
	r.OnCriticalPaths(context.Background(), []analyzer.AttackPath{pathToRepo("victim/infra")})
	if len(fp.calls) != 0 {
		t.Fatalf("posted a commit status to a repository outside the allowlist: %v", fp.calls)
	}
	// The allowed repository still works - the guard bounds writes, it does not stop them.
	r.OnCriticalPaths(context.Background(), []analyzer.AttackPath{pathToRepo("acme/web")})
	if len(fp.calls) != 1 {
		t.Fatalf("allowed repository got %d status calls, want 1", len(fp.calls))
	}
}

func TestCommenterRefusesRepoOutsideAllowlist(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		t.Errorf("commenter called the forge for a disallowed repository: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewGitHubCommenter(GitHubConfig{Token: "t", BaseURL: srv.URL, Allow: mustAllow(t, "acme/*")})
	c.OnCriticalPaths(context.Background(), []analyzer.AttackPath{pathToRepo("victim/infra")})
	if hits != 0 {
		t.Fatalf("made %d call(s) to the forge", hits)
	}
}

func TestPROpenerRefusesRepoOutsideAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("pr opener called the forge for a disallowed repository: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	o := NewGitHubPROpener(GitHubConfig{Token: "ghp_x", BaseURL: srv.URL, Allow: mustAllow(t, "acme/*")})
	_, err := o.OpenPR(context.Background(), OpenPRRequest{
		Slug: "victim/infra", Branch: "pg/fix-1", Title: "t",
		Files: []PRFile{{Path: "a.tf", Content: "x"}},
	})
	if !errors.Is(err, ErrRepoNotAllowed) {
		t.Fatalf("OpenPR error = %v, want ErrRepoNotAllowed", err)
	}
}

// Dry-run makes no outbound call, so it is exempt from the allowlist: the demo and a
// first run without any forge configuration keep printing what they would post. This
// is guarded because the obvious "tighten it everywhere" change silently empties the
// demo's output, and nothing else would notice.
func TestDryRunIsExemptFromTheAllowlist(t *testing.T) {
	fp := &fakeStatusDryRun{}
	r := newStatusReporter(fp, nil, "") // nil allowlist: denies every REAL write
	r.OnCriticalPaths(context.Background(), []analyzer.AttackPath{pathToRepo("acme/web")})
	if fp.calls != 1 {
		t.Fatalf("dry-run reporter made %d call(s), want 1 (it logs, it does not write)", fp.calls)
	}
}

type fakeStatusDryRun struct{ calls int }

func (f *fakeStatusDryRun) forge() string { return "github" }
func (f *fakeStatusDryRun) enabled() bool { return false }
func (f *fakeStatusDryRun) postStatus(context.Context, string, string, string, string, string) error {
	f.calls++
	return nil
}
