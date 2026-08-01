package action

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A token-less configuration must fall back to dry-run rather than posting and failing
// on every analysis pass: an unconfigured install should be quiet, not broken.
func TestNoTokenFallsBackToDryRun(t *testing.T) {
	if r := NewGitHubChecker(GitHubConfig{}, ""); r == nil {
		t.Fatal("NewGitHubChecker returned nil")
	}
	g := &githubStatusPoster{cfg: GitHubConfig{}}
	if g.enabled() {
		t.Error("a poster with no token reported itself enabled; it would try to post on every pass")
	}
	if g.forge() != "github" {
		t.Errorf("forge() = %q", g.forge())
	}
}

func TestDryRunIsNotOverriddenByAToken(t *testing.T) {
	g := &githubStatusPoster{cfg: GitHubConfig{Token: "t", DryRun: true}}
	if g.enabled() {
		t.Error("DryRun was overridden by the presence of a token")
	}
}

// GitHub rejects a status description over 140 characters. Clamping here keeps the
// check visible: a clipped sentence is better than the whole PR check vanishing into an
// API error.
func TestClampDescRespectsTheAPILimit(t *testing.T) {
	short := "internet → payments-admin: 1 reachable path"
	if got := clampDesc(short); got != short {
		t.Errorf("a short description was altered: %q", got)
	}
	if exact := strings.Repeat("y", 140); clampDesc(exact) != exact {
		t.Error("a description of exactly the limit was truncated")
	}

	got := clampDesc(strings.Repeat("x", 300))
	if len([]rune(got)) > 140 {
		t.Errorf("clamped description is %d runes, want at most 140", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncation is unmarked, so the text merely looks cut off: %q", got)
	}
}

// Dry-run must not touch the network at all, so an install without a token can run in
// an air-gapped environment without a failed connection on every pass.
func TestDryRunPostsNothing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()

	g := &githubStatusPoster{cfg: GitHubConfig{BaseURL: srv.URL, DryRun: true}, http: srv.Client()}
	if err := g.postStatus(context.Background(), "acme/api", "deadbeef", "failure", "1 path", ""); err != nil {
		t.Fatalf("dry-run returned an error: %v", err)
	}
	if hits != 0 {
		t.Errorf("dry-run made %d HTTP calls", hits)
	}
}

// This payload is what turns a reachable path into a red merge gate, so it has to carry
// the state and the context GitHub keys the required check on.
func TestConfiguredPosterSendsTheStatus(t *testing.T) {
	var body map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	g := &githubStatusPoster{cfg: GitHubConfig{BaseURL: srv.URL, Token: "t"}, http: srv.Client()}
	if err := g.postStatus(context.Background(), "acme/api", "deadbeef", "failure", "1 reachable path", "https://dash"); err != nil {
		t.Fatalf("postStatus: %v", err)
	}
	if !strings.Contains(path, "/repos/acme/api/statuses/deadbeef") {
		t.Errorf("posted to %q", path)
	}
	if body["state"] != "failure" {
		t.Errorf("state = %v, want failure - the gate would stay green on a real path", body["state"])
	}
	if s, _ := body["context"].(string); s == "" {
		t.Error("no context set, so the check cannot be marked required in branch protection")
	}
	if body["target_url"] != "https://dash" {
		t.Errorf("target_url = %v, so a reviewer has no link to the evidence", body["target_url"])
	}
}

// The target URL is optional; omitting it must send no key at all, because an empty one
// renders as a dead link on the PR.
func TestNoTargetURLIsOmittedRatherThanEmpty(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	g := &githubStatusPoster{cfg: GitHubConfig{BaseURL: srv.URL, Token: "t"}, http: srv.Client()}
	if err := g.postStatus(context.Background(), "acme/api", "sha", "success", "clear", ""); err != nil {
		t.Fatalf("postStatus: %v", err)
	}
	if _, present := body["target_url"]; present {
		t.Error("an empty target_url was sent, which renders as a dead link")
	}
}

func TestPostStatusSurfacesAnAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	g := &githubStatusPoster{cfg: GitHubConfig{BaseURL: srv.URL, Token: "bad"}, http: srv.Client()}
	err := g.postStatus(context.Background(), "acme/api", "sha", "failure", "1 path", "")
	if err == nil {
		t.Fatal("a 401 was reported as a successful post, so a broken token would look like a green gate")
	}
}

// ── sinks ───────────────────────────────────────────────────────────────────

type countingSink struct{ n int }

func (c *countingSink) OnCriticalPaths(context.Context, []analyzer.AttackPath) { c.n++ }

// MultiSink is how one analysis pass reaches the PR comment, the merge gate and the
// alert webhook at once. Stopping after the first would let one channel's problem
// silently take out the others.
func TestMultiSinkFansOutToEverySink(t *testing.T) {
	a, b, c := &countingSink{}, &countingSink{}, &countingSink{}
	MultiSink{a, b, c}.OnCriticalPaths(context.Background(), nil)
	if a.n != 1 || b.n != 1 || c.n != 1 {
		t.Fatalf("fan-out reached %d/%d/%d, want 1 each", a.n, b.n, c.n)
	}
}

func TestEmptyMultiSinkIsSafe(t *testing.T) {
	MultiSink{}.OnCriticalPaths(context.Background(), nil) // must not panic
}

func TestConsoleSinkRendersAPathWithoutPanicking(t *testing.T) {
	p := analyzer.AttackPath{
		ID: "p1",
		Nodes: []ontology.Node{
			{ID: "lb", Name: "edge-alb", Label: ontology.LabelLoadBalancer},
			{ID: "role", Name: "payments-admin", Label: ontology.LabelIAMRole},
		},
		Steps: []analyzer.Step{{From: "lb", To: "role", EdgeType: ontology.EdgeExposes, Probability: 0.9}},
		Score: 0.55,
	}
	ConsoleSink{}.OnCriticalPaths(context.Background(), []analyzer.AttackPath{p})
	ConsoleSink{}.OnCriticalPaths(context.Background(), nil)
}
