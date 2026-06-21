package action

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GitLabConfig configures the GitLab merge-request commenter.
type GitLabConfig struct {
	Token   string // personal/project access token with `api` scope
	BaseURL string // API base; defaults to https://gitlab.com/api/v4
	DryRun  bool
}

// NewGitLabCommenter returns a Commenter that posts to GitLab merge requests.
// The path's repo_slug is used as the URL-encoded project path ("group/project")
// and pr_number as the merge-request IID.
func NewGitLabCommenter(cfg GitLabConfig) *Commenter {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://gitlab.com/api/v4"
	}
	if cfg.Token == "" && !cfg.DryRun {
		slog.Warn("gitlab commenter: no token set, running in dry-run (comments logged, not posted)")
		cfg.DryRun = true
	}
	return newCommenter(&gitlabPoster{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}})
}

type gitlabPoster struct {
	cfg  GitLabConfig
	http *http.Client
}

type glNote struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func (g *gitlabPoster) forge() string { return "gitlab" }
func (g *gitlabPoster) enabled() bool { return !g.cfg.DryRun && g.cfg.Token != "" }

func (g *gitlabPoster) headers() map[string]string {
	return map[string]string{"PRIVATE-TOKEN": g.cfg.Token}
}

func (g *gitlabPoster) notesURL(ref prRef) string {
	// project path must be URL-encoded, e.g. group%2Fproject
	return fmt.Sprintf("%s/projects/%s/merge_requests/%d/notes",
		g.cfg.BaseURL, url.PathEscape(ref.slug), ref.number)
}

// find pages through every note on the MR looking for the marker (same
// rationale as the GitHub poster: the marker may sit beyond the first page).
func (g *gitlabPoster) find(ctx context.Context, ref prRef, marker string) (string, error) {
	for page := 1; page <= maxCommentPages; page++ {
		pageURL := fmt.Sprintf("%s?per_page=100&page=%d", g.notesURL(ref), page)
		var notes []glNote
		if err := requestJSON(ctx, g.http, http.MethodGet, pageURL, g.headers(), nil, &notes); err != nil {
			return "", err
		}
		for _, n := range notes {
			if strings.Contains(n.Body, marker) {
				return strconv.FormatInt(n.ID, 10), nil
			}
		}
		if len(notes) < 100 {
			break // last page
		}
	}
	return "", nil
}

func (g *gitlabPoster) create(ctx context.Context, ref prRef, body string) error {
	return requestJSON(ctx, g.http, http.MethodPost, g.notesURL(ref), g.headers(), map[string]string{"body": body}, nil)
}

func (g *gitlabPoster) update(ctx context.Context, ref prRef, commentID, body string) error {
	url := g.notesURL(ref) + "/" + commentID
	return requestJSON(ctx, g.http, http.MethodPut, url, g.headers(), map[string]string{"body": body}, nil)
}
