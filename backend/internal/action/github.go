package action

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GitHubConfig configures the GitHub PR commenter.
type GitHubConfig struct {
	Token   string // token with `pull_requests: write` (e.g. GITHUB_TOKEN in CI)
	BaseURL string // API base; defaults to https://api.github.com (override for GHE)
	DryRun  bool   // log the comment instead of calling the API
}

// NewGitHubCommenter returns a Commenter that posts to GitHub pull requests.
func NewGitHubCommenter(cfg GitHubConfig) *Commenter {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.github.com"
	}
	if cfg.Token == "" && !cfg.DryRun {
		slog.Warn("github commenter: no token set, running in dry-run (comments logged, not posted)")
		cfg.DryRun = true
	}
	return newCommenter(&githubPoster{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}})
}

type githubPoster struct {
	cfg  GitHubConfig
	http *http.Client
}

type ghComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func (g *githubPoster) forge() string { return "github" }
func (g *githubPoster) enabled() bool { return !g.cfg.DryRun && g.cfg.Token != "" }

func (g *githubPoster) headers() map[string]string { return githubHeaders(g.cfg.Token) }

// githubHeaders are the auth + versioning headers for the GitHub REST API, shared
// by the PR commenter, the status checker, and the remediation PR opener.
func githubHeaders(token string) map[string]string {
	return map[string]string{
		"Authorization":        "Bearer " + token,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
}

// find pages through every comment on the PR looking for the marker: stopping
// at the first page would re-create (duplicate) the comment on busy PRs where
// the marker sits beyond the first 100.
func (g *githubPoster) find(ctx context.Context, ref prRef, marker string) (string, error) {
	owner, repo, ok := splitSlug(ref.slug)
	if !ok {
		return "", fmt.Errorf("invalid github slug %q", ref.slug)
	}
	for page := 1; page <= maxCommentPages; page++ {
		url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments?per_page=100&page=%d",
			g.cfg.BaseURL, owner, repo, ref.number, page)
		var comments []ghComment
		if err := requestJSON(ctx, g.http, http.MethodGet, url, g.headers(), nil, &comments); err != nil {
			return "", err
		}
		for _, c := range comments {
			if strings.Contains(c.Body, marker) {
				return strconv.FormatInt(c.ID, 10), nil
			}
		}
		if len(comments) < 100 {
			break // last page
		}
	}
	return "", nil
}

func (g *githubPoster) create(ctx context.Context, ref prRef, body string) error {
	owner, repo, _ := splitSlug(ref.slug)
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", g.cfg.BaseURL, owner, repo, ref.number)
	return requestJSON(ctx, g.http, http.MethodPost, url, g.headers(), map[string]string{"body": body}, nil)
}

func (g *githubPoster) update(ctx context.Context, ref prRef, commentID, body string) error {
	owner, repo, _ := splitSlug(ref.slug)
	url := fmt.Sprintf("%s/repos/%s/%s/issues/comments/%s", g.cfg.BaseURL, owner, repo, commentID)
	return requestJSON(ctx, g.http, http.MethodPatch, url, g.headers(), map[string]string{"body": body}, nil)
}

func splitSlug(slug string) (owner, repo string, ok bool) {
	owner, repo, ok = strings.Cut(slug, "/")
	return owner, repo, ok && owner != "" && repo != ""
}
