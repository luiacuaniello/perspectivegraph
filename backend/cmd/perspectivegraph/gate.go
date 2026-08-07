package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
)

// The exit codes are the whole interface: a CI runner reads them, not the prose.
//
// The one that matters is gateExitUnknown. Every other scanner in a pipeline has two
// outcomes, and a pipeline whose scanner output never arrived gets the same green light
// as a pipeline that is genuinely clean. That silent pass is the failure this tool exists
// to make visible, so "nobody looked at this commit" gets its own code and, by default,
// fails the build. Turning it into a pass is possible (-allow-unknown) but it is a
// decision an operator has to take on purpose.
const (
	gateExitClean   = 0
	gateExitBlocked = 1
	gateExitUnknown = 2
	gateExitError   = 3
)

// gateVerdict mirrors the prVerdict GraphQL type.
type gateVerdict struct {
	Analysed      bool   `json:"analysed"`
	CriticalPaths int    `json:"criticalPaths"`
	AnalysedAt    string `json:"analysedAt"`
	Paths         []struct {
		ID       string  `json:"id"`
		Score    float64 `json:"score"`
		Priority float64 `json:"priority"`
		Nodes    []struct {
			Name  string `json:"name"`
			Label string `json:"label"`
		} `json:"nodes"`
	} `json:"paths"`
}

// runGate is the merge gate: push one scanner report into the engine stamped with the
// pull request's identity, wait for the engine to place it in the estate graph, and fail
// the build when the change puts a sensitive asset within reach.
//
// It deliberately blocks on ATTACK PATHS, not on vulnerability counts. A critical CVE on
// a host nothing can route to does not fail the build; a medium one on a container that
// now reaches the production database does. That is the entire point, and it is why this
// runs against a live estate rather than inside the pipeline sandbox.
func runGate(args []string) error {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	report := fs.String("report", "", "scanner report to ingest (\"-\" for stdin). Empty polls only, for when something else already ingested.")
	source := fs.String("source", "trivy", "collector that parses -report (trivy, semgrep, ...); the /ingest/{source} route")
	slug := fs.String("slug", os.Getenv("GITHUB_REPOSITORY"), "repository, \"owner/name\"")
	sha := fs.String("sha", os.Getenv("GITHUB_SHA"), "commit SHA under test")
	pr := fs.Int("pr", 0, "pull-request number, if any")
	repo := fs.String("repo", "", "repository identity for reports that carry file paths but not the repo (defaults to -slug)")
	ingest := fs.String("ingest", envOr("INGEST_URL", "http://localhost:8081"), "ingest base URL")
	api := fs.String("api", envOr("API_URL", "http://localhost:8080"), "API base URL")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token, if API auth is on")
	secret := fs.String("hmac-secret", os.Getenv("INGEST_HMAC_SECRET"), "shared secret signing the ingest body, if the webhook requires it")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for a verdict before reporting UNKNOWN")
	poll := fs.Duration("poll", 5*time.Second, "interval between verdict checks")
	maxCritical := fs.Int("max-critical", 0, "fail when the commit is on more than this many critical paths")
	allowUnknown := fs.Bool("allow-unknown", false, "pass the build when the commit was never analysed. This turns a broken ingest into a green check - reasonable while rolling the gate out, a liability afterwards.")
	asJSON := fs.Bool("json", false, "print the verdict as JSON instead of prose")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *slug == "" || *sha == "" {
		return errors.New("-slug and -sha are required (GITHUB_REPOSITORY and GITHUB_SHA supply them on GitHub Actions)")
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// The freshness floor. `analysed` is answered from the graph and `criticalPaths`
	// from the last analyzer pass, so a commit can be present while the paths still
	// describe the estate as it was before it arrived - which reads as zero. Requiring a
	// pass strictly newer than our own ingest closes that gap.
	//
	// It only applies when we ingested. On a steady graph the analyzer skips recomputing
	// for up to ten ticks, so in poll-only mode a floor would time out on a verdict that
	// was already correct, and turn a clean build red.
	var floor time.Time
	if *report != "" {
		body, err := readGateReport(*report)
		if err != nil {
			return err
		}
		if *repo == "" {
			*repo = *slug
		}
		floor = time.Now().UTC()
		if err := postGateReport(client, *ingest, *source, *slug, *sha, *repo, *pr, *token, *secret, body); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "gate: ingested %s report for %s@%s\n", *source, *slug, shortSHA(*sha))
	}

	v, err := waitForVerdict(client, *api, *token, *slug, *sha, floor, *timeout, *poll)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
	} else {
		printGateVerdict(os.Stdout, v, *slug, *sha, *maxCritical)
	}

	switch {
	case !v.Analysed:
		if *allowUnknown {
			fmt.Fprintln(os.Stderr, "gate: UNKNOWN, passing anyway because -allow-unknown was set")
			os.Exit(gateExitClean)
		}
		os.Exit(gateExitUnknown)
	case v.CriticalPaths > *maxCritical:
		os.Exit(gateExitBlocked)
	}
	os.Exit(gateExitClean)
	return nil
}

func shortSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

func readGateReport(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	b, err := os.ReadFile(path) // #nosec G304 G703 -- operator-supplied path to their own scanner output
	if err != nil {
		return nil, fmt.Errorf("read -report: %w", err)
	}
	return b, nil
}

// postGateReport sends the report to /ingest/{source} with the pull request's identity in
// the query string, which is what stamps repo_slug and commit_sha onto the asset node and
// so makes the commit findable later.
func postGateReport(client *http.Client, base, source, slug, sha, repo string, pr int, token, secret string, body []byte) error {
	q := url.Values{"slug": {slug}, "sha": {sha}}
	if repo != "" {
		q.Set("repo", repo)
	}
	if pr > 0 {
		q.Set("pr", strconv.Itoa(pr))
	}
	endpoint := strings.TrimSuffix(base, "/") + "/ingest/" + url.PathEscape(source) + "?" + q.Encode()

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if secret != "" {
		req.Header.Set(auth.SignatureHeader, auth.Sign(secret, body))
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /ingest/%s: %w", source, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("POST /ingest/%s returned %d: %s", source, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return nil
}

const gateQuery = `query($slug:String!,$sha:String!){prVerdict(slug:$slug,sha:$sha){analysed criticalPaths analysedAt paths{id score priority nodes{name label}}}}`

// waitForVerdict polls until the engine has an answer about this commit, or gives up.
// Giving up is reported as "not analysed", so the caller's UNKNOWN handling covers a
// timeout too: an engine that never answered told us exactly as much as one that never
// saw the commit.
func waitForVerdict(client *http.Client, base, token, slug, sha string, floor time.Time, timeout, poll time.Duration) (gateVerdict, error) {
	deadline := time.Now().Add(timeout)
	var last gateVerdict
	for {
		v, err := fetchVerdict(client, base, token, slug, sha)
		if err != nil {
			return gateVerdict{}, err
		}
		last = v
		if v.Analysed && verdictIsFresh(v, floor) {
			return v, nil
		}
		if !time.Now().Add(poll).Before(deadline) {
			last.Analysed = false
			return last, nil
		}
		time.Sleep(poll)
	}
}

// verdictIsFresh reports whether the pass behind this verdict ran after the floor. An
// unparseable or absent timestamp counts as stale rather than fresh: the gate then waits
// and eventually reports UNKNOWN, which is the honest answer when the engine will not say
// when it looked.
func verdictIsFresh(v gateVerdict, floor time.Time) bool {
	if floor.IsZero() {
		return true
	}
	at, err := time.Parse(time.RFC3339Nano, v.AnalysedAt)
	if err != nil {
		return false
	}
	return at.After(floor)
}

func fetchVerdict(client *http.Client, base, token, slug, sha string) (gateVerdict, error) {
	body, err := json.Marshal(map[string]any{
		"query":     gateQuery,
		"variables": map[string]string{"slug": slug, "sha": sha},
	})
	if err != nil {
		return gateVerdict{}, err
	}
	st, rb, err := apiRequest(client, http.MethodPost, strings.TrimSuffix(base, "/")+"/graphql", token, body)
	if err != nil {
		return gateVerdict{}, fmt.Errorf("POST /graphql: %w", err)
	}
	if st >= 300 {
		return gateVerdict{}, fmt.Errorf("POST /graphql returned %d: %s", st, strings.TrimSpace(string(rb)))
	}

	var out struct {
		Data struct {
			PRVerdict gateVerdict `json:"prVerdict"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return gateVerdict{}, fmt.Errorf("decode verdict: %w", err)
	}
	if len(out.Errors) > 0 {
		return gateVerdict{}, fmt.Errorf("prVerdict: %s", out.Errors[0].Message)
	}
	return out.Data.PRVerdict, nil
}

// printGateVerdict says what was decided and, when it blocks, what it blocked on. A gate
// that only reports that it blocked sends the engineer hunting; naming the route it found
// is the difference between a useful gate and an obstacle.
func printGateVerdict(w io.Writer, v gateVerdict, slug, sha string, maxCritical int) {
	switch {
	case !v.Analysed:
		fmt.Fprintf(w, "UNKNOWN  %s@%s\n", slug, shortSHA(sha))
		fmt.Fprintln(w, "  Nothing carrying this commit reached the engine, so nobody analysed it.")
		fmt.Fprintln(w, "  This is NOT a clean result. Check that the scan ran and that the ingest URL,")
		fmt.Fprintln(w, "  the HMAC secret and the -slug/-sha values are the ones this engine expects.")
	case v.CriticalPaths > maxCritical:
		fmt.Fprintf(w, "BLOCKED  %s@%s: %d critical attack path(s) run through this commit\n", slug, shortSHA(sha), v.CriticalPaths)
		for i, p := range v.Paths {
			if i == 5 {
				fmt.Fprintf(w, "  ... and %d more\n", len(v.Paths)-5)
				break
			}
			hops := make([]string, 0, len(p.Nodes))
			for _, n := range p.Nodes {
				hops = append(hops, n.Name)
			}
			fmt.Fprintf(w, "  [P%.0f] %s\n", p.Priority, strings.Join(hops, " -> "))
		}
	default:
		fmt.Fprintf(w, "CLEAN    %s@%s: analysed, no critical path reaches a sensitive asset through it\n", slug, shortSHA(sha))
	}
}
