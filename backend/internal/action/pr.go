package action

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// PRFile is one file committed in a remediation pull request.
type PRFile struct {
	Path    string
	Content string
}

// OpenPRRequest is a request to open a remediation pull request.
type OpenPRRequest struct {
	Slug   string // "owner/repo"
	Branch string // head branch to create, e.g. "perspectivegraph/fix-<id>"
	Title  string
	Body   string
	Files  []PRFile
}

// PROpener opens a pull request carrying a set of files — the "close the loop"
// step that turns a generated remediation into an actual PR a human can review
// and merge, instead of a suggestion to copy by hand. Abstracted so the API
// endpoint is testable with a fake; the live GitHub flow is validated against a
// real token.
type PROpener interface {
	Enabled() bool
	OpenPR(ctx context.Context, req OpenPRRequest) (url string, err error)
}

// NewGitHubPROpener returns a PROpener backed by the GitHub REST API.
func NewGitHubPROpener(cfg GitHubConfig) PROpener {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.github.com"
	}
	return &githubPROpener{cfg: cfg, http: &http.Client{Timeout: 20 * time.Second}}
}

type githubPROpener struct {
	cfg  GitHubConfig
	http *http.Client
}

func (g *githubPROpener) Enabled() bool { return !g.cfg.DryRun && g.cfg.Token != "" }

// OpenPR branches off the repo's default branch, commits each file, and opens a
// PR back to that default branch. Returns the PR's html_url.
func (g *githubPROpener) OpenPR(ctx context.Context, req OpenPRRequest) (string, error) {
	if !g.Enabled() {
		return "", errors.New("github pr opener disabled (set GITHUB_TOKEN)")
	}
	if req.Slug == "" || req.Branch == "" || len(req.Files) == 0 {
		return "", errors.New("pr opener: slug, branch and at least one file are required")
	}
	h := githubHeaders(g.cfg.Token)
	api := g.cfg.BaseURL + "/repos/" + req.Slug

	// 1. default branch + its head sha.
	var repo struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := requestJSON(ctx, g.http, http.MethodGet, api, h, nil, &repo); err != nil {
		return "", fmt.Errorf("get repo: %w", err)
	}
	defaultBranch := repo.DefaultBranch
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := requestJSON(ctx, g.http, http.MethodGet, api+"/git/ref/heads/"+defaultBranch, h, nil, &ref); err != nil {
		return "", fmt.Errorf("get base ref: %w", err)
	}

	// 2. create the head branch off the base.
	if err := requestJSON(ctx, g.http, http.MethodPost, api+"/git/refs", h,
		map[string]any{"ref": "refs/heads/" + req.Branch, "sha": ref.Object.SHA}, nil); err != nil {
		return "", fmt.Errorf("create branch %q: %w", req.Branch, err)
	}

	// 3. commit each file onto the branch (new files).
	for _, f := range req.Files {
		if err := requestJSON(ctx, g.http, http.MethodPut, api+"/contents/"+f.Path, h, map[string]any{
			"message": req.Title,
			"content": base64.StdEncoding.EncodeToString([]byte(f.Content)),
			"branch":  req.Branch,
		}, nil); err != nil {
			return "", fmt.Errorf("commit %s: %w", f.Path, err)
		}
	}

	// 4. open the PR.
	var pr struct {
		HTMLURL string `json:"html_url"`
	}
	if err := requestJSON(ctx, g.http, http.MethodPost, api+"/pulls", h, map[string]any{
		"title": req.Title, "head": req.Branch, "base": defaultBranch, "body": req.Body,
	}, &pr); err != nil {
		return "", fmt.Errorf("open pr: %w", err)
	}
	return pr.HTMLURL, nil
}

// nopPROpener is the default when no GitHub token is configured.
type nopPROpener struct{}

func (nopPROpener) Enabled() bool { return false }
func (nopPROpener) OpenPR(context.Context, OpenPRRequest) (string, error) {
	return "", errors.New("remediation-as-PR is not configured (set GITHUB_TOKEN)")
}

// NopPROpener returns a disabled opener.
func NopPROpener() PROpener { return nopPROpener{} }
