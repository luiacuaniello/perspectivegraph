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
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
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
//
// Which paths count against a commit is the merge gate's rule (see impact.Ledger): the
// routes the change opened or made likelier, not every route through an asset it
// touched. Without a ledger, every route through the commit counts - the rule before
// 1.22, kept by PR_ATTRIBUTION=commit.
type StatusReporter struct {
	p         statusPoster
	allow     *RepoAllow // where writes are permitted; nil denies everything
	targetURL string
	judge     *impact.Ledger // nil: every route through a commit counts against it
	mu        sync.Mutex
	// failing holds the commits currently red, per tenant, with the description posted -
	// so they can be cleared, and so an unchanged verdict is not posted again on every
	// pass (GitHub keeps at most 1,000 statuses per commit and context).
	failing map[string]failingStatus
}

type commitRef struct{ slug, sha string }

type failingStatus struct {
	ref  commitRef
	desc string
}

func newStatusReporter(p statusPoster, allow *RepoAllow, targetURL string) *StatusReporter {
	return &StatusReporter{p: p, allow: allow, targetURL: targetURL, failing: map[string]failingStatus{}}
}

// permitted reports whether a status may be posted on this repository. The slug is a
// node property - untrusted input choosing a write destination (see repoguard.go) -
// and a commit status is the one write that can OPEN a gate rather than close it: a
// `success` on a commit in a repository where this check is required. Dry-run is
// exempt; it makes no outbound call.
func (s *StatusReporter) permitted(slug string) bool {
	if !s.p.enabled() || s.allow.Permit(slug) {
		return true
	}
	slog.Warn("pr check refused: repository not allowed",
		"forge", s.p.forge(), "slug", slug, "hint", "add it to REPO_ALLOWLIST")
	return false
}

// tally is one commit's standing in a pass.
type tally struct {
	ref         commitRef
	counted     int  // routes that count against it
	recorded    bool // some counted by the per-commit rule, for want of a "before"
	later       bool // some appeared through it after it arrived
	preexisting int  // routes through it that were there before it
}

func (s *StatusReporter) OnCriticalPaths(ctx context.Context, tenant string, paths []analyzer.AttackPath) {
	// Judge every path against every commit it runs through. A route through two
	// changes - an image from one repository, a deployment from another - is a question
	// for each of them: the one that opened it may well be the second.
	tallies := map[string]*tally{}
	for _, p := range paths {
		for _, ref := range commitsOn(p) {
			if !s.permitted(ref.slug) {
				continue
			}
			key := tenant + "\x00" + ref.slug + "@" + ref.sha
			t := tallies[key]
			if t == nil {
				t = &tally{ref: ref}
				tallies[key] = t
			}
			v := s.judge.Judge(tenant, ref.slug, ref.sha, p)
			switch {
			case !v.Counts:
				t.preexisting++
			case v.Change == impact.Recorded:
				t.counted++
				t.recorded = true
			case v.Change == impact.Later:
				t.counted++
				t.later = true
			default:
				t.counted++
			}
		}
	}

	for key, t := range tallies {
		if t.counted == 0 {
			continue
		}
		desc := s.failureDescription(t)
		s.mu.Lock()
		unchanged := s.failing[key].desc == desc
		s.mu.Unlock()
		if unchanged {
			continue
		}
		if err := s.p.postStatus(ctx, t.ref.slug, t.ref.sha, "failure", desc, s.targetURL); err != nil {
			slog.Error("pr check failed", "forge", s.p.forge(), "slug", t.ref.slug, "sha", short(t.ref.sha), "err", err)
			continue
		}
		s.mu.Lock()
		s.failing[key] = failingStatus{ref: t.ref, desc: desc}
		s.mu.Unlock()
	}

	// Clear: a commit of this tenant that was red and no longer has a route counting
	// against it goes green. Another tenant's commits are not this pass's to judge.
	s.mu.Lock()
	var resolved []string
	for key := range s.failing {
		if !strings.HasPrefix(key, tenant+"\x00") {
			continue
		}
		if t := tallies[key]; t == nil || t.counted == 0 {
			resolved = append(resolved, key)
		}
	}
	s.mu.Unlock()
	for _, key := range resolved {
		s.mu.Lock()
		ref := s.failing[key].ref
		s.mu.Unlock()
		desc := "No critical attack path from this change"
		if s.judge.Enabled() {
			desc = "No critical attack path opened by this change"
			if t := tallies[key]; t != nil && t.preexisting > 0 {
				desc += fmt.Sprintf(" (%d already there pass through it)", t.preexisting)
			}
		}
		if err := s.p.postStatus(ctx, ref.slug, ref.sha, "success", desc, s.targetURL); err != nil {
			slog.Error("pr check resolve failed", "forge", s.p.forge(), "slug", ref.slug, "err", err)
			continue
		}
		s.mu.Lock()
		delete(s.failing, key)
		s.mu.Unlock()
		slog.Info("pr check cleared (now green)", "forge", s.p.forge(), "slug", ref.slug, "sha", short(ref.sha))
	}
}

// failureDescription says why a commit is red, in the words of the rule that made it so.
func (s *StatusReporter) failureDescription(t *tally) string {
	switch {
	case !s.judge.Enabled():
		return fmt.Sprintf("%d critical attack path(s) reach a sensitive asset from this change", t.counted)
	case t.recorded:
		return fmt.Sprintf("%d critical attack path(s) pass through this commit, in the graph before the engine was watching", t.counted)
	}
	what := "opened or made likelier by this change"
	if t.later {
		what = "opened or made likelier since this change arrived"
	}
	if t.preexisting > 0 {
		return fmt.Sprintf("%d critical attack path(s) %s (%d already there)", t.counted, what, t.preexisting)
	}
	return fmt.Sprintf("%d critical attack path(s) %s", t.counted, what)
}

// commitsOn lists the distinct pull-request commits stamped on a path's nodes - the
// coordinates a commit status needs - in path order.
func commitsOn(p analyzer.AttackPath) []commitRef {
	var out []commitRef
	seen := map[commitRef]bool{}
	for _, n := range p.Nodes {
		s, _ := n.Properties[ontology.PropRepoSlug].(string)
		c, _ := n.Properties[ontology.PropCommitSHA].(string)
		ref := commitRef{s, c}
		if c != "" && ValidSlug(s) && !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	return out
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
	r := newStatusReporter(&githubStatusPoster{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}, cfg.Allow, targetURL)
	r.judge = cfg.Attribution
	return r
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
