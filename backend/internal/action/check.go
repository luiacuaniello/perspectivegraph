package action

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// statusContext is the GitHub status "context" - the check name shown on the PR
// and the one a branch-protection rule names to make this a required gate.
const statusContext = "perspectivegraph/attack-paths"

// statusPoster abstracts the forge commit-status call so the reporter is testable
// with a fake. slug is "owner/repo"; sha is the commit the status attaches to.
type statusPoster interface {
	forge() string
	enabled() bool
	postStatus(ctx context.Context, slug, sha, state, description, targetURL string) error
}

// StatusReporter turns the analyzer into a merge gate: when a change sits on a
// critical internet→crown-jewel path it fails that PR's commit status, and once
// the PR no longer does it flips the status green. It satisfies analyzer.Sink, so
// the same pass that flags a path fails its PR's check - shift-left, not a comment
// you can ignore. Make it a *required* status check in branch protection to block
// the merge.
type StatusReporter struct {
	p         statusPoster
	targetURL string
	mu        sync.Mutex
	failing   map[string]commitRef // "slug@sha" currently red, so we can clear them
}

type commitRef struct{ slug, sha string }

func newStatusReporter(p statusPoster, targetURL string) *StatusReporter {
	return &StatusReporter{p: p, targetURL: targetURL, failing: map[string]commitRef{}}
}

func (s *StatusReporter) OnCriticalPaths(ctx context.Context, paths []analyzer.AttackPath) {
	// Group the critical paths by the PR commit they touch.
	counts := map[string]int{}
	refs := map[string]commitRef{}
	for _, p := range paths {
		slug, sha, ok := commitTarget(p)
		if !ok {
			continue // no PR commit context on this path
		}
		key := slug + "@" + sha
		counts[key]++
		refs[key] = commitRef{slug, sha}
	}

	for key, ref := range refs {
		desc := fmt.Sprintf("%d critical attack path(s) reach a sensitive asset from this change", counts[key])
		if err := s.p.postStatus(ctx, ref.slug, ref.sha, "failure", desc, s.targetURL); err != nil {
			slog.Error("pr check failed", "forge", s.p.forge(), "slug", ref.slug, "sha", short(ref.sha), "err", err)
			continue
		}
		s.mu.Lock()
		s.failing[key] = ref
		s.mu.Unlock()
	}

	// Clear: a PR that was red and is no longer on a critical path goes green.
	s.mu.Lock()
	var resolved []commitRef
	for key, ref := range s.failing {
		if _, still := refs[key]; !still {
			resolved = append(resolved, ref)
			delete(s.failing, key)
		}
	}
	s.mu.Unlock()
	for _, ref := range resolved {
		if err := s.p.postStatus(ctx, ref.slug, ref.sha, "success", "No critical attack path from this change", s.targetURL); err != nil {
			slog.Error("pr check resolve failed", "forge", s.p.forge(), "slug", ref.slug, "err", err)
			continue
		}
		slog.Info("pr check cleared (now green)", "forge", s.p.forge(), "slug", ref.slug, "sha", short(ref.sha))
	}
}

// commitTarget finds the first node carrying both a repo slug and a commit SHA -
// the coordinates a GitHub commit status needs.
func commitTarget(p analyzer.AttackPath) (slug, sha string, ok bool) {
	for _, n := range p.Nodes {
		s, _ := n.Properties[ontology.PropRepoSlug].(string)
		c, _ := n.Properties[ontology.PropCommitSHA].(string)
		if s != "" && c != "" && strings.Contains(s, "/") {
			return s, c, true
		}
	}
	return "", "", false
}

func short(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

// ── GitHub commit-status poster ──────────────────────────────────────

// NewGitHubChecker returns a StatusReporter that posts GitHub commit statuses.
// targetURL (optional) deep-links the check back to the dashboard.
func NewGitHubChecker(cfg GitHubConfig, targetURL string) *StatusReporter {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.github.com"
	}
	if cfg.Token == "" && !cfg.DryRun {
		slog.Warn("github pr check: no token set, running in dry-run (status logged, not posted)")
		cfg.DryRun = true
	}
	return newStatusReporter(&githubStatusPoster{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}, targetURL)
}

type githubStatusPoster struct {
	cfg  GitHubConfig
	http *http.Client
}

func (g *githubStatusPoster) forge() string { return "github" }
func (g *githubStatusPoster) enabled() bool { return !g.cfg.DryRun && g.cfg.Token != "" }

func (g *githubStatusPoster) postStatus(ctx context.Context, slug, sha, state, description, targetURL string) error {
	if !g.enabled() {
		slog.Info("pr check (dry-run)", "slug", slug, "sha", short(sha), "state", state, "desc", description)
		return nil
	}
	body := map[string]any{"state": state, "context": statusContext, "description": clampDesc(description)}
	if targetURL != "" {
		body["target_url"] = targetURL
	}
	url := fmt.Sprintf("%s/repos/%s/statuses/%s", g.cfg.BaseURL, slug, sha)
	return requestJSON(ctx, g.http, http.MethodPost, url, githubHeaders(g.cfg.Token), body, nil)
}

// clampDesc keeps a status description within GitHub's 140-char limit.
func clampDesc(s string) string {
	if len(s) <= 140 {
		return s
	}
	return s[:137] + "…"
}
