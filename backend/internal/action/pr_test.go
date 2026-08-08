package action

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The PR opener is the ONLY component that writes outside this product's own boundary:
// it creates a branch and commits files in the customer's repository, with a
// write-scoped token. It had no tests at all.
//
// What matters here is not that the happy path returns a URL, but the shape of what it
// does with that token - which repository, which branch, which files, and that the
// credential travels in a header rather than anywhere it could be logged or cached.

// call records one request the fake GitHub saw.
type call struct {
	method string
	path   string
	body   map[string]any
	auth   string
	query  string
}

// fakeGitHub answers the five requests OpenPR makes, and records them.
func fakeGitHub(t *testing.T, fail map[string]int) (*httptest.Server, *[]call) {
	t.Helper()
	var mu sync.Mutex
	var calls []call

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			_ = json.Unmarshal(b, &body)
		}
		mu.Lock()
		calls = append(calls, call{
			method: r.Method, path: r.URL.Path, body: body,
			auth: r.Header.Get("Authorization"), query: r.URL.RawQuery,
		})
		mu.Unlock()

		if code, ok := fail[r.Method+" "+r.URL.Path]; ok {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, `{"message":"nope"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_, _ = io.WriteString(w, `{"object":{"sha":"basesha123"}}`)
		case r.Method == http.MethodGet:
			_, _ = io.WriteString(w, `{"default_branch":"main"}`)
		case strings.HasSuffix(r.URL.Path, "/pulls"):
			_, _ = io.WriteString(w, `{"html_url":"https://github.com/acme/payments/pull/7"}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func opener(t *testing.T, srv *httptest.Server) PROpener {
	t.Helper()
	return NewGitHubPROpener(GitHubConfig{Token: "ghp_secret", BaseURL: srv.URL})
}

func request() OpenPRRequest {
	return OpenPRRequest{
		Slug:   "acme/payments",
		Branch: "perspectivegraph/fix-abc",
		Title:  "Close the route to secrets-vault",
		Files:  []PRFile{{Path: "terraform/sg.tf", Content: "resource \"aws_security_group\" {}"}},
	}
}

// The whole flow, asserted on what actually reached GitHub: the branch is cut from the
// default branch's commit, the file is committed onto that branch, and the PR targets
// the default branch. A branch cut from the wrong base silently proposes reverting
// whatever landed in between.
func TestOpenPRBranchesFromTheDefaultBranchAndCommitsThere(t *testing.T) {
	srv, calls := fakeGitHub(t, nil)
	url, err := opener(t, srv).OpenPR(context.Background(), request())
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if url != "https://github.com/acme/payments/pull/7" {
		t.Errorf("returned %q, not the PR's html_url", url)
	}

	got := *calls
	if len(got) != 5 {
		t.Fatalf("made %d requests, want 5 (repo, ref, branch, file, pull): %+v", len(got), got)
	}
	for _, c := range got {
		if !strings.Contains(c.path, "/repos/acme/payments") {
			t.Errorf("a request went to %q, outside the requested repository", c.path)
		}
	}

	branch := got[2]
	if branch.body["ref"] != "refs/heads/perspectivegraph/fix-abc" {
		t.Errorf("branch ref = %v", branch.body["ref"])
	}
	if branch.body["sha"] != "basesha123" {
		t.Errorf("branch cut from %v, not the default branch's head - the PR would revert intervening commits", branch.body["sha"])
	}

	file := got[3]
	if file.method != http.MethodPut || !strings.HasSuffix(file.path, "/contents/terraform/sg.tf") {
		t.Errorf("file committed via %s %s", file.method, file.path)
	}
	if file.body["branch"] != "perspectivegraph/fix-abc" {
		t.Errorf("file committed onto %v, not the new branch - that would write to the default branch directly",
			file.body["branch"])
	}
	if enc, _ := file.body["content"].(string); enc != "" {
		if _, err := base64.StdEncoding.DecodeString(enc); err != nil {
			t.Errorf("file content is not base64 as the API requires: %v", err)
		}
	}

	pull := got[4]
	if pull.body["head"] != "perspectivegraph/fix-abc" || pull.body["base"] != "main" {
		t.Errorf("PR opened %v -> %v", pull.body["head"], pull.body["base"])
	}
}

// The token is a write-scoped credential for someone else's repository. It must travel
// in the Authorization header and nowhere else - a query string is logged by proxies,
// kept in browser history and echoed in error pages.
func TestTokenTravelsOnlyInTheAuthorizationHeader(t *testing.T) {
	srv, calls := fakeGitHub(t, nil)
	if _, err := opener(t, srv).OpenPR(context.Background(), request()); err != nil {
		t.Fatal(err)
	}
	for _, c := range *calls {
		if !strings.Contains(c.auth, "ghp_secret") {
			t.Errorf("%s %s carried no credential in Authorization", c.method, c.path)
		}
		if strings.Contains(c.query, "ghp_secret") || strings.Contains(c.path, "ghp_secret") {
			t.Errorf("%s %s leaked the token into the URL", c.method, c.path)
		}
	}
}

// Every step can fail, and a failure must stop the flow rather than carry on and open a
// PR against a branch that was never created.
func TestOpenPRStopsAtTheFirstFailure(t *testing.T) {
	for name, path := range map[string]string{
		"repo lookup":   "GET /repos/acme/payments",
		"base ref":      "GET /repos/acme/payments/git/ref/heads/main",
		"create branch": "POST /repos/acme/payments/git/refs",
		"commit file":   "PUT /repos/acme/payments/contents/terraform/sg.tf",
		"open pull":     "POST /repos/acme/payments/pulls",
	} {
		t.Run(name, func(t *testing.T) {
			srv, calls := fakeGitHub(t, map[string]int{path: http.StatusForbidden})
			url, err := opener(t, srv).OpenPR(context.Background(), request())
			if err == nil {
				t.Fatalf("a 403 on %s was reported as success (url=%q)", path, url)
			}
			if url != "" {
				t.Errorf("returned a URL alongside an error: %q", url)
			}
			// Nothing may be attempted after the step that failed.
			for i, c := range *calls {
				if c.method+" "+c.path == path && i != len(*calls)-1 {
					t.Errorf("%d more request(s) went out after %s failed", len(*calls)-1-i, path)
				}
			}
		})
	}
}

// Refusing to act is the safe default: no token, or dry-run, means no write to anyone's
// repository. A disabled opener that quietly did nothing and reported success would be
// worse - the operator would believe a fix had been proposed.
func TestDisabledOpenerRefusesInsteadOfSilentlyDoingNothing(t *testing.T) {
	for name, cfg := range map[string]GitHubConfig{
		"no token": {Token: "", BaseURL: "http://127.0.0.1:1"},
		"dry run":  {Token: "ghp_secret", DryRun: true, BaseURL: "http://127.0.0.1:1"},
	} {
		t.Run(name, func(t *testing.T) {
			o := NewGitHubPROpener(cfg)
			if o.Enabled() {
				t.Fatal("reported enabled")
			}
			if _, err := o.OpenPR(context.Background(), request()); err == nil {
				t.Error("OpenPR succeeded while disabled, so the caller believes a PR exists")
			}
		})
	}
}

// The incomplete requests, each of which would otherwise reach GitHub and fail there -
// or worse, half-succeed by creating a branch with nothing on it.
func TestOpenPRRejectsIncompleteRequests(t *testing.T) {
	srv, calls := fakeGitHub(t, nil)
	o := opener(t, srv)
	for name, req := range map[string]OpenPRRequest{
		"no slug":   {Branch: "b", Files: []PRFile{{Path: "p", Content: "c"}}},
		"no branch": {Slug: "acme/payments", Files: []PRFile{{Path: "p", Content: "c"}}},
		"no files":  {Slug: "acme/payments", Branch: "b"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := o.OpenPR(context.Background(), req); err == nil {
				t.Error("accepted")
			}
		})
	}
	if n := len(*calls); n != 0 {
		t.Errorf("%d request(s) reached GitHub for requests that should never have left", n)
	}
}

// The no-op opener is what runs when the feature is off. It must be inert and honest.
func TestNopOpenerIsInertAndSaysSo(t *testing.T) {
	o := NopPROpener()
	if o.Enabled() {
		t.Error("the no-op opener reported enabled")
	}
	if url, err := o.OpenPR(context.Background(), request()); err == nil || url != "" {
		t.Errorf("OpenPR returned (%q, %v); it must refuse", url, err)
	}
}
