package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/action"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type fakeOpener struct {
	enabled bool
	called  bool
	req     action.OpenPRRequest
}

func (f *fakeOpener) Enabled() bool { return f.enabled }
func (f *fakeOpener) OpenPR(_ context.Context, req action.OpenPRRequest) (string, error) {
	f.called = true
	f.req = req
	return "https://github.com/acme/web/pull/7", nil
}

// seedPRPath puts an internet→container→crown-jewel path (with PR repo context)
// in the default tenant and runs one analyzer pass; returns the path id.
func seedPRPath(t *testing.T, a *API) string {
	t.Helper()
	ctx := context.Background()
	store, err := a.manager.For(ctx, auth.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	must(store.UpsertNode(ctx, ontology.Node{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "alb",
		Properties: map[string]any{ontology.PropInternetExposed: true, ontology.PropRepoSlug: "acme/web", ontology.PropCommitSHA: "abc123"}}))
	must(store.UpsertNode(ctx, ontology.Node{ID: "c1", Label: ontology.LabelContainer, Name: "web"}))
	must(store.UpsertNode(ctx, ontology.Node{ID: "role", Label: ontology.LabelIAMRole, Name: "admin",
		Properties: map[string]any{ontology.PropCrownJewel: true}}))
	must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: "lb", To: "c1", ExploitProbability: 0.9}))
	must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeAssumes, From: "c1", To: "role", ExploitProbability: 0.8}))

	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = a.analyzer.Run(runCtx) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ps := a.analyzer.Latest(auth.DefaultTenant); len(ps) > 0 {
			return ps[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("analyzer produced no path to test against")
	return ""
}

func TestOpenRemediationPR(t *testing.T) {
	a, _ := testAPI(t)
	fo := &fakeOpener{enabled: true}
	a.WithRemediationPR(fo)
	pathID := seedPRPath(t, a)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/remediation/pr", strings.NewReader(`{"pathId":"`+pathID+`"}`))
	a.openRemediationPR(rec, req.WithContext(viewerCtx())) // open mode → adminWritable true

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !fo.called {
		t.Fatal("opener was not called")
	}
	if fo.req.Slug != "acme/web" {
		t.Errorf("PR slug = %q, want acme/web", fo.req.Slug)
	}
	if len(fo.req.Files) == 0 {
		t.Error("PR opened with no remediation files")
	}
	if !strings.HasPrefix(fo.req.Branch, "perspectivegraph/fix-") {
		t.Errorf("branch = %q, want perspectivegraph/fix-… prefix", fo.req.Branch)
	}
}

func TestOpenRemediationPRDisabled(t *testing.T) {
	a, _ := testAPI(t)
	a.WithRemediationPR(&fakeOpener{enabled: false})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/remediation/pr", strings.NewReader(`{"pathId":"x"}`))
	a.openRemediationPR(rec, req.WithContext(viewerCtx()))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("disabled opener should be 503, got %d", rec.Code)
	}
}

func TestOpenRemediationPRUnknownPath(t *testing.T) {
	a, _ := testAPI(t)
	a.WithRemediationPR(&fakeOpener{enabled: true})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/remediation/pr", strings.NewReader(`{"pathId":"nope"}`))
	a.openRemediationPR(rec, req.WithContext(viewerCtx()))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path should be 404, got %d", rec.Code)
	}
}

// refusingOpener is the real opener's answer for a repository outside REPO_ALLOWLIST.
type refusingOpener struct{ called bool }

func (o *refusingOpener) Enabled() bool { return true }
func (o *refusingOpener) OpenPR(context.Context, action.OpenPRRequest) (string, error) {
	o.called = true
	return "", fmt.Errorf("%w: %q", action.ErrRepoNotAllowed, "victim/infra")
}

// A repository the operator never named is a configuration answer, not a bad gateway:
// the caller did nothing wrong and retrying will not help. It must also not echo the
// forge's response body back, which is how a 502 leaks whether a private repo exists.
func TestOpenRemediationPRRefusesRepoOutsideAllowlist(t *testing.T) {
	a, _ := testAPI(t)
	o := &refusingOpener{}
	a.WithRemediationPR(o)
	id := seedPRPath(t, a)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/remediation/pr", strings.NewReader(`{"pathId":"`+id+`"}`))
	a.openRemediationPR(rec, req.WithContext(viewerCtx()))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("refused repository should be 422, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "REPO_ALLOWLIST") {
		t.Errorf("the error should name the setting to fix; got %s", rec.Body.String())
	}
	if !o.called {
		t.Error("the opener was never consulted, so the guard is in the wrong place")
	}
}

// The slug is read from a node property. A malformed one must never reach a URL: it is
// dropped at resolution, so the request fails as "no repository context" instead.
func TestRepoSlugOfRejectsMalformedSlugs(t *testing.T) {
	for _, bad := range []string{"../../user/repos", "acme", "acme/we b", "acme/..", ""} {
		p := analyzer.AttackPath{Nodes: []ontology.Node{
			{ID: "n", Properties: map[string]any{ontology.PropRepoSlug: bad}},
		}}
		if got := repoSlugOf(p); got != "" {
			t.Errorf("repoSlugOf(%q) = %q, want it dropped", bad, got)
		}
	}
	p := analyzer.AttackPath{Nodes: []ontology.Node{
		{ID: "n", Properties: map[string]any{ontology.PropRepoSlug: "acme/web"}},
	}}
	if got := repoSlugOf(p); got != "acme/web" {
		t.Errorf("repoSlugOf(valid) = %q, want acme/web", got)
	}
}

type failingOpener struct{ err error }

func (o *failingOpener) Enabled() bool { return true }
func (o *failingOpener) OpenPR(context.Context, action.OpenPRRequest) (string, error) {
	return "", o.err
}

// The forge's own error carries the URL that was requested and up to 2KB of its answer,
// and GitHub answers differently for "no such repository" and "no access to it". Echoed
// to the caller that is an oracle for private repository names and for what the token
// can reach, so the detail goes to the log and the caller gets the status.
func TestOpenRemediationPRDoesNotEchoTheForgeResponse(t *testing.T) {
	a, _ := testAPI(t)
	a.WithRemediationPR(&failingOpener{err: fmt.Errorf(
		"create branch: POST https://api.github.com/repos/acme/secret-infra/git/refs: 404 Not Found: " +
			`{"message":"Not Found","documentation_url":"https://docs.github.com/rest"}`)})
	id := seedPRPath(t, a)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/remediation/pr", strings.NewReader(`{"pathId":"`+id+`"}`))
	a.openRemediationPR(rec, req.WithContext(viewerCtx()))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	for _, leak := range []string{"api.github.com", "secret-infra", "404", "documentation_url"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("the response repeated %q from the forge's answer: %s", leak, rec.Body.String())
		}
	}
}
