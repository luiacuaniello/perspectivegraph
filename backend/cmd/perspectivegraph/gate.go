package main

import (
	"bytes"
	"context"
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

// gateVerdict mirrors the prVerdict GraphQL type and the POST /gate/impact answer. It is
// the contract between the ways of reaching a verdict - asking a running engine, per
// commit or by comparison, or computing it here in local mode - so that everything
// downstream cannot tell them apart.
type gateVerdict struct {
	// Attribution is how routes were attributed to the change: "diff" (the routes it
	// opens or worsens, the default) or "commit" (every route through an asset stamped
	// with the commit, the rule before 1.22).
	Attribution   string     `json:"attribution"`
	Analysed      bool       `json:"analysed"`
	CriticalPaths int        `json:"criticalPaths"`
	AnalysedAt    string     `json:"analysedAt"`
	Paths         []gatePath `json:"paths"`

	// Diff attribution only. Preexisting counts routes through the change's assets that
	// were there before it; Recorded, that the engine already held the commit, so routes
	// through it counted per commit; Reachable, that some asset of the change can be
	// reached from an attack seed at all.
	Preexisting int  `json:"preexisting,omitempty"`
	Recorded    bool `json:"recorded,omitempty"`
	Reachable   bool `json:"reachable,omitempty"`

	// Incomplete is set (to the reason) when the estate was read only in part, which
	// local mode can detect and the server cannot. A path found on partial data is
	// still a real path, so BLOCKED survives - but "no path" on partial data is not
	// clean, it is unknown, and it is reported as such.
	Incomplete string `json:"incomplete,omitempty"`
}

type gatePath struct {
	ID       string     `json:"id"`
	Score    float64    `json:"score"`
	Priority float64    `json:"priority"`
	Nodes    []gateNode `json:"nodes"`
	// Diff attribution: why the route counts (introduced, worsened, recorded), the score
	// a worsened route had before, and whether its assets are hidden from this token.
	Change        string  `json:"change,omitempty"`
	PreviousScore float64 `json:"previousScore,omitempty"`
	Redacted      bool    `json:"redacted,omitempty"`
}

type gateNode struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// runGate is the merge gate: fail the build when the change puts a sensitive asset
// within reach.
//
// By default it asks what the change ADDS: the report is applied to a copy of the estate
// and the routes it opens or worsens are what count (-attribution diff; POST
// /gate/impact on a server, the same comparison in local mode). The rule before 1.22 -
// every route through an asset stamped with the commit - is -attribution commit: it
// ingests the report and waits for the engine's record of the commit, and it blocked a
// change for routes that were there before it (a rescanned image, a re-rendered
// deployment).
//
// It deliberately blocks on ATTACK PATHS, not on vulnerability counts. A critical CVE on
// a host nothing can route to does not fail the build; a medium one on a container that
// now reaches the production database does. That is the entire point, and it is why this
// runs against a live estate rather than inside the pipeline sandbox.
func runGate(args []string) error {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	report := fs.String("report", "", "scanner report to ingest (\"-\" for stdin). Empty polls only, for when something else already ingested.")
	source := fs.String("source", "trivy", "collector that parses -report (trivy, semgrep, ...); the /ingest/{source} route")
	local := fs.Bool("local", false, "compute the verdict in this process instead of polling a running engine: read the estate read-only, ingest -report, and answer here. Needs no deployment.")
	estate := fs.String("estate", "", "local mode: estate as an events JSON file, the format `awscollect -json` writes")
	awsRegion := fs.String("aws-region", "", "local mode: read the estate live from this AWS region (read-only)")
	awsRole := fs.String("aws-role", "", "local mode: cross-account read-only role to assume for -aws-region")
	var reports reportFlag
	fs.Var(&reports, "reports", "local mode: repeatable scanner report as source=path (e.g. -reports trivy=t.json -reports semgrep=s.json)")
	slug := fs.String("slug", os.Getenv("GITHUB_REPOSITORY"), "repository, \"owner/name\"")
	sha := fs.String("sha", os.Getenv("GITHUB_SHA"), "commit SHA under test")
	pr := fs.Int("pr", 0, "pull-request number, if any")
	repo := fs.String("repo", "", "repository identity for reports that carry file paths but not the repo (defaults to -slug)")
	ingest := fs.String("ingest", envOr("INGEST_URL", "http://localhost:8081"), "ingest base URL")
	api := fs.String("api", envOr("API_URL", "http://localhost:8080"), "API base URL")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token, if API auth is on")
	secret := fs.String("hmac-secret", os.Getenv("INGEST_HMAC_SECRET"), "shared secret signing the ingest request, if the webhook requires it (sent as HMAC v2, which covers the time, path and commit parameters, and as v1 for engines older than 1.20)")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for a verdict before reporting UNKNOWN")
	poll := fs.Duration("poll", 5*time.Second, "interval between verdict checks")
	maxCritical := fs.Int("max-critical", 0, "fail when the commit is on more than this many critical paths")
	allowUnknown := fs.Bool("allow-unknown", false, "pass the build when the commit was never analysed. This turns a broken ingest into a green check - reasonable while rolling the gate out, a liability afterwards.")
	asJSON := fs.Bool("json", false, "print the verdict as JSON instead of prose")
	attribution := fs.String("attribution", "diff", "which routes count against the change: \"diff\" - the ones it opens or worsens, compared with the estate as it stands, and nothing is written - or \"commit\" - every route through an asset stamped with the commit, the rule before 1.22")
	persist := fs.Bool("persist", false, "diff attribution, server mode: also send the report to the ingest webhook, so the live graph records the change (the engine's own PR comments need it). The verdict is computed first, on the estate without it")
	var baseReports reportFlag
	fs.Var(&baseReports, "base-reports", "local mode, diff attribution: repeatable source=path scan of what runs now (the base branch), applied to the estate before the comparison - without it a scanned image is compared with an estate that knows none of its findings")
	if err := fs.Parse(args); err != nil {
		return err
	}
	stdin, err := drainStdinReport(os.Stdin, *report, reports)
	if err != nil {
		return err
	}
	if *slug == "" || *sha == "" {
		return errors.New("-slug and -sha are required (GITHUB_REPOSITORY and GITHUB_SHA supply them on GitHub Actions)")
	}
	switch *attribution {
	case "diff", "commit":
	default:
		return fmt.Errorf("-attribution %q: want diff or commit", *attribution)
	}
	if len(baseReports) > 0 && !*local {
		return errors.New("-base-reports is for local mode: a server compares with the estate it already holds")
	}
	for _, b := range baseReports {
		if b.path == "-" {
			return errors.New("-base-reports cannot read stdin: it carries this change's report")
		}
	}

	// Local mode short-circuits every remote concern - no ingest, no polling, no
	// freshness floor, because the graph is built and read once in this process. From
	// here down the two modes converge: the same verdict shape, the same printing, the
	// same exit codes.
	if *local {
		if *report != "" {
			if err := reports.Set(*source + "=" + *report); err != nil {
				return err
			}
		}
		specs, err := reports.resolveSources(*source)
		if err != nil {
			return err
		}
		if *repo == "" {
			*repo = *slug
		}
		base, err := baseReports.resolveSources(*source)
		if err != nil {
			return err
		}
		v, err := localVerdict(context.Background(), localOpts{
			slug: *slug, sha: *sha, pr: *pr, repository: *repo,
			reports: specs, baseReports: base, estate: *estate,
			awsRegion: *awsRegion, awsRole: *awsRole,
			stdin: stdin, attribution: *attribution,
		})
		if err != nil {
			return err
		}
		reportAndExit(v, *slug, *sha, *maxCritical, *allowUnknown, *asJSON)
	}

	if *repo == "" {
		*repo = *slug
	}
	var body []byte
	if *report != "" {
		b, err := readGateReport(*report, stdin)
		if err != nil {
			return err
		}
		body = b
	}
	v, err := serverVerdict(serverOpts{
		client: &http.Client{Timeout: 30 * time.Second},
		api:    *api, ingest: *ingest, token: *token, secret: *secret,
		source: *source, slug: *slug, sha: *sha, repo: *repo, pr: *pr,
		report: body, attribution: *attribution, persist: *persist,
		timeout: *timeout, poll: *poll,
	}, os.Stderr)
	if err != nil {
		return err
	}
	reportAndExit(v, *slug, *sha, *maxCritical, *allowUnknown, *asJSON)
	return nil
}

// serverOpts is what asking a running engine for a verdict takes.
type serverOpts struct {
	client                     *http.Client
	api, ingest, token, secret string
	source, slug, sha, repo    string
	pr                         int
	report                     []byte // nil: poll only, something else ingested
	attribution                string
	persist                    bool
	timeout, poll              time.Duration
}

// serverVerdict asks a running engine what it makes of the change: by comparison when
// there is a report and the engine can compare, otherwise from its record of the commit.
// Notes on how it got there go to log.
func serverVerdict(o serverOpts, log io.Writer) (gateVerdict, error) {
	attr := o.attribution
	if attr == "diff" && o.report == nil {
		// Poll-only: something else ingested the commit, and there is no report here to
		// compare. The engine's record of the commit is all there is to go on.
		fmt.Fprintln(log, "gate: no -report to compare with the estate, so this is the engine's record of the commit (-attribution commit)")
		attr = "commit"
	}
	if attr == "diff" {
		v, err := postImpact(o.client, o.api, o.source, o.slug, o.sha, o.repo, o.pr, o.token, o.report)
		switch {
		case errors.Is(err, errNoImpact):
			// An engine older than 1.22 has no comparison to offer. Falling back keeps the
			// pipeline working through an upgrade of the action ahead of the engine, and the
			// verdict says which rule produced it.
			fmt.Fprintln(log, "gate: this engine predates POST /gate/impact, so the verdict is its record of the commit (-attribution commit); upgrade it to compare")
		case err != nil:
			return gateVerdict{}, err
		default:
			if o.persist {
				if _, err := postGateReport(o.client, o.ingest, o.source, o.slug, o.sha, o.repo, o.pr, o.token, o.secret, o.report); err != nil {
					// The verdict stands - it was computed without the report in the graph -
					// but whoever asked for the write must hear that it did not happen.
					fmt.Fprintf(log, "gate: the verdict stands, but -persist failed: %v\n", err)
				} else {
					fmt.Fprintf(log, "gate: recorded the %s report for %s@%s in the live graph\n", o.source, o.slug, shortSHA(o.sha))
				}
			}
			return v, nil
		}
	}

	// The freshness floor. `analysed` is answered from the graph and `criticalPaths`
	// from the last analyzer pass, so a commit can be present while the paths still
	// describe the estate as it was before it arrived - which reads as zero. Requiring a
	// pass strictly newer than our own ingest closes that gap.
	//
	// It only applies when we ingested. On a steady graph the analyzer skips recomputing
	// for up to ten ticks, so in poll-only mode a floor would time out on a verdict that
	// was already correct, and turn a clean build red.
	var floor time.Time
	if o.report != nil {
		floor = time.Now().UTC()
		batch, err := postGateReport(o.client, o.ingest, o.source, o.slug, o.sha, o.repo, o.pr, o.token, o.secret, o.report)
		if err != nil {
			return gateVerdict{}, err
		}
		fmt.Fprintf(log, "gate: ingested %s report for %s@%s\n", o.source, o.slug, shortSHA(o.sha))
		// A large report reaches the graph as several messages, and a pass that ran
		// between them analysed part of it - possibly the part that is clean. So the
		// floor moves to when the LAST message was applied. An engine too old to return a
		// batch keeps the floor at our own post, as before.
		if batch != "" {
			applied, done, err := waitForBatch(o.client, o.api, o.token, batch, deadlineFrom(o.timeout), o.poll)
			if err != nil {
				return gateVerdict{}, err
			}
			if !done {
				fmt.Fprintf(log, "gate: the report never fully reached the graph (batch %s)\n", batch)
				return gateVerdict{Attribution: "commit"}, nil
			}
			if applied.After(floor) {
				floor = applied
			}
		}
	}

	v, err := waitForVerdict(o.client, o.api, o.token, o.slug, o.sha, floor, o.timeout, o.poll)
	if err != nil {
		return gateVerdict{}, err
	}
	v.Attribution = "commit"
	return v, nil
}

// errNoImpact is an engine without POST /gate/impact - one older than 1.22.
var errNoImpact = errors.New("the engine has no /gate/impact")

// postImpact asks the engine what the change adds to the estate's attack paths: the
// report goes to POST /gate/impact with the same parameters the ingest webhook takes, and
// the answer is the verdict. The API authenticates it with the bearer token; nothing is
// written, so it needs no ingest signature.
func postImpact(client *http.Client, base, source, slug, sha, repo string, pr int, token string, body []byte) (gateVerdict, error) {
	q := url.Values{"source": {source}, "slug": {slug}, "sha": {sha}}
	if repo != "" {
		q.Set("repo", repo)
	}
	if pr > 0 {
		q.Set("pr", strconv.Itoa(pr))
	}
	endpoint := strings.TrimSuffix(base, "/") + "/gate/impact?" + q.Encode()
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return gateVerdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return gateVerdict{}, fmt.Errorf("POST /gate/impact: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	// 404 or 405 without a JSON error of ours: the route does not exist, the engine is
	// older. A JSON 404 is ours - an unknown collector, the gate disabled - and an error.
	if (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) && !isJSONError(rb) {
		return gateVerdict{}, errNoImpact
	}
	if resp.StatusCode >= 300 {
		return gateVerdict{}, fmt.Errorf("POST /gate/impact returned %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var v gateVerdict
	if err := json.Unmarshal(rb, &v); err != nil {
		return gateVerdict{}, fmt.Errorf("decode the gate's answer: %w", err)
	}
	return v, nil
}

func isJSONError(b []byte) bool {
	var e struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(b, &e) == nil && e.Error != ""
}

// reportAndExit renders a verdict and turns it into this process's exit code. Both modes
// end here, which is what makes local mode a different way to OBTAIN the verdict rather
// than a second gate with its own opinions about what blocks a build.
func reportAndExit(v gateVerdict, slug, sha string, maxCritical int, allowUnknown, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			fmt.Fprintln(os.Stderr, "gate:", err)
			os.Exit(gateExitError)
		}
	} else {
		printGateVerdict(os.Stdout, v, slug, sha, maxCritical)
	}

	switch {
	case !v.Analysed, v.Incomplete != "" && v.CriticalPaths <= maxCritical:
		if allowUnknown {
			fmt.Fprintln(os.Stderr, "gate: UNKNOWN, passing anyway because -allow-unknown was set")
			os.Exit(gateExitClean)
		}
		os.Exit(gateExitUnknown)
	case v.CriticalPaths > maxCritical:
		os.Exit(gateExitBlocked)
	}
	os.Exit(gateExitClean)
}

func shortSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

func readGateReport(path string, stdin []byte) ([]byte, error) {
	if path == "-" {
		return stdin, nil // already drained by runGate, see drainStdinReport
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
// postGateReport sends a report to ingest and returns the batch id the engine gave it -
// empty from an engine too old to track batches.
func postGateReport(client *http.Client, base, source, slug, sha, repo string, pr int, token, secret string, body []byte) (string, error) {
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
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if secret != "" {
		// Both signatures: v2 covers the timestamp, the path and the commit parameters, and
		// an engine that knows it checks only that one; v1 keeps an engine older than v2
		// accepting the report.
		ts := time.Now().Unix()
		req.Header.Set(auth.SignatureHeader, auth.Sign(secret, body))
		req.Header.Set(auth.TimestampHeader, strconv.FormatInt(ts, 10))
		req.Header.Set(auth.SignatureV2Header, auth.SignV2(secret, ts, http.MethodPost, "/ingest/"+url.PathEscape(source), q, body))
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /ingest/%s: %w", source, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("POST /ingest/%s returned %d: %s", source, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var accepted struct {
		Batch string `json:"batch"`
	}
	_ = json.Unmarshal(rb, &accepted) // an older engine's response has no batch
	return accepted.Batch, nil
}

func deadlineFrom(timeout time.Duration) time.Time { return time.Now().Add(timeout) }

const batchQuery = `query($id:String!){ingestBatch(id:$id){complete appliedAt}}`

// waitForBatch polls until every message of an ingest batch has been applied, returning
// when the last one was. done is false when the deadline passed first - or when the
// engine will not say, which the caller treats the same way: it cannot claim the verdict
// covers the whole report.
func waitForBatch(client *http.Client, base, token, id string, deadline time.Time, poll time.Duration) (applied time.Time, done bool, err error) {
	body, err := json.Marshal(map[string]any{"query": batchQuery, "variables": map[string]string{"id": id}})
	if err != nil {
		return time.Time{}, false, err
	}
	for {
		st, rb, err := apiRequest(client, http.MethodPost, strings.TrimSuffix(base, "/")+"/graphql", token, body)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("POST /graphql: %w", err)
		}
		if st >= 300 {
			return time.Time{}, false, fmt.Errorf("POST /graphql returned %d: %s", st, strings.TrimSpace(string(rb)))
		}
		var out struct {
			Data struct {
				IngestBatch *struct {
					Complete  bool   `json:"complete"`
					AppliedAt string `json:"appliedAt"`
				} `json:"ingestBatch"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rb, &out); err != nil {
			return time.Time{}, false, fmt.Errorf("decode batch: %w", err)
		}
		if b := out.Data.IngestBatch; b != nil && b.Complete {
			at, err := time.Parse(time.RFC3339Nano, b.AppliedAt)
			if err != nil {
				return time.Time{}, false, nil
			}
			return at, true, nil
		}
		if !time.Now().Add(poll).Before(deadline) {
			return time.Time{}, false, nil
		}
		time.Sleep(poll)
	}
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
	case v.Incomplete != "" && v.CriticalPaths <= maxCritical:
		// Not clean: the engine found no route, but it did not see the whole estate, and
		// a route through the part it could not read looks exactly like no route at all.
		fmt.Fprintf(w, "UNKNOWN  %s@%s\n", slug, shortSHA(sha))
		fmt.Fprintf(w, "  The estate was read only in part, so \"no attack path\" cannot be trusted:\n  %s\n", v.Incomplete)
		fmt.Fprintln(w, "  This is NOT a clean result. Fix the estate access and run it again.")
	case v.CriticalPaths > maxCritical && v.Attribution == "diff" && !v.Recorded:
		fmt.Fprintf(w, "BLOCKED  %s@%s: this change opens or worsens %d critical attack path(s)\n", slug, shortSHA(sha), v.CriticalPaths)
		printPaths(w, v.Paths)
	case v.CriticalPaths > maxCritical && v.Attribution == "diff":
		fmt.Fprintf(w, "BLOCKED  %s@%s: %d critical attack path(s) count against this change\n", slug, shortSHA(sha), v.CriticalPaths)
		printPaths(w, v.Paths)
	case v.CriticalPaths > maxCritical:
		fmt.Fprintf(w, "BLOCKED  %s@%s: %d critical attack path(s) run through this commit\n", slug, shortSHA(sha), v.CriticalPaths)
		printPaths(w, v.Paths)
	case v.Attribution == "diff":
		fmt.Fprintf(w, "CLEAN    %s@%s: analysed, this change opens or worsens no critical attack path\n", slug, shortSHA(sha))
	default:
		fmt.Fprintf(w, "CLEAN    %s@%s: analysed, no critical path reaches a sensitive asset through it\n", slug, shortSHA(sha))
	}
	if v.Attribution != "diff" || !v.Analysed {
		return
	}
	if v.Preexisting > 0 {
		fmt.Fprintf(w, "  %d existing route(s) run through the change's assets. They were there before it, so they do not count.\n", v.Preexisting)
	}
	if v.Recorded {
		fmt.Fprintln(w, "  The engine already held this commit (-persist, or another step posting the same scan), so the")
		fmt.Fprintln(w, "  comparison cannot tell its routes from older ones: routes through it count as the per-commit gate counts them.")
	}
	if !v.Reachable {
		fmt.Fprintln(w, "  None of the change's assets can be reached from an attack seed. If it runs somewhere, check that the")
		fmt.Fprintln(w, "  scanned image is named as the workload runs it - a mismatch looks exactly like this.")
	}
}

// printPaths lists what a verdict blocked on, the first five of them.
func printPaths(w io.Writer, paths []gatePath) {
	for i, p := range paths {
		if i == 5 {
			fmt.Fprintf(w, "  ... and %d more\n", len(paths)-5)
			break
		}
		if p.Redacted {
			fmt.Fprintf(w, "  [P%.0f] %sa route outside the applications this token may read\n", p.Priority, changeLabel(p))
			continue
		}
		hops := make([]string, 0, len(p.Nodes))
		for _, n := range p.Nodes {
			hops = append(hops, n.Name)
		}
		fmt.Fprintf(w, "  [P%.0f] %s%s\n", p.Priority, changeLabel(p), strings.Join(hops, " -> "))
	}
}

// changeLabel says why a route counts, under diff attribution; nothing under commit.
func changeLabel(p gatePath) string {
	switch p.Change {
	case "introduced":
		return "new: "
	case "worsened":
		return fmt.Sprintf("worse, %.0f%% -> %.0f%%: ", p.PreviousScore*100, p.Score*100)
	case "recorded":
		return "through this commit: "
	}
	return ""
}
