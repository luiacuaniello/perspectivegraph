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
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
)

// runIngest sends one scanner report to a running engine, signed the way its ingestion
// endpoint requires - the step every CI job and cron job used to rebuild by hand, with
// openssl and the five-line string the signature covers:
//
//	perspectivegraph ingest trivy trivy.json
//	perspectivegraph ingest -slug acme/app -sha "$GITHUB_SHA" -pr 42 semgrep semgrep.json
//	kubectl get … -A -o json | perspectivegraph ingest -cluster prod-eu k8s -
//
// The endpoint is INGEST_URL (-url); the secret is INGEST_HMAC_SECRET, or the file
// INGEST_HMAC_SECRET_FILE names (-hmac-secret). Only the v2 signature is sent: it covers the
// time, the path and the attribution parameters, so a captured request can be neither
// replayed nor pointed at another commit, and an engine can stop accepting v1 altogether.
// That needs an engine of 1.20 or later.
//
// Each attempt is signed afresh. A v2 signature is accepted once, so resending the same one
// after a timeout or a 503 - which may have come after the engine accepted it - would be
// refused as a replay. -wait holds until the engine has applied the report to the graph,
// for a job whose next step reads it.
func runIngest(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	base := fs.String("url", envOr("INGEST_URL", "http://localhost:8081"), "ingestion base URL (INGEST_URL)")
	secret := fs.String("hmac-secret", "", "secret signing the request (default: INGEST_HMAC_SECRET, or the file INGEST_HMAC_SECRET_FILE names)")
	tenant := fs.String("tenant", "", "tenant the report belongs to (X-Tenant), when the engine keeps one secret per tenant")
	repo := fs.String("repo", "", "repository identity, for reports that carry file paths but not the repository")
	slug := fs.String("slug", "", "repository as \"owner/name\", attributing the report to a commit or pull request")
	sha := fs.String("sha", "", "commit SHA the report was produced from")
	pr := fs.Int("pr", 0, "pull-request number")
	account := fs.String("account", "", "AWS account the report describes, for identifiers unique only within one account")
	cluster := fs.String("cluster", "", "Kubernetes cluster the report describes: names repeat across clusters")
	snapshot := fs.String("snapshot", "", "declare the report complete for a scope (e.g. cluster:prod), so what it no longer lists is retracted; \"none\" for a filtered scan")
	retries := fs.Int("retries", 3, "attempts after the first, on a network error, a 429 or a 5xx")
	wait := fs.Bool("wait", false, "wait until the engine has applied the report to the graph")
	api := fs.String("api", envOr("API_URL", "http://localhost:8080"), "API base URL, for -wait (API_URL)")
	token := fs.String("token", os.Getenv("API_TOKEN"), "API bearer token, for -wait when the API requires one (API_TOKEN)")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long -wait waits")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: perspectivegraph ingest [flags] <source> <file|->")
		fmt.Fprintln(fs.Output(), "  source: the collector, as in /ingest/{source} - trivy, semgrep, k8s, custodian, falco, iam, cloudnet, ...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return errors.New("want a source and a file (or - for stdin)")
	}
	source, path := fs.Arg(0), fs.Arg(1)
	if *retries < 0 {
		return errors.New("-retries cannot be negative")
	}

	key, err := ingestSecret(*secret)
	if err != nil {
		return err
	}
	body, err := readReport(path, stdin)
	if err != nil {
		return err
	}

	q := url.Values{}
	for k, v := range map[string]string{"repo": *repo, "slug": *slug, "sha": *sha, "account": *account, "cluster": *cluster, "snapshot": *snapshot} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if *pr > 0 {
		q.Set("pr", strconv.Itoa(*pr))
	}

	client := &http.Client{Timeout: time.Minute}
	var accepted ingestReply
	for attempt := 0; ; attempt++ {
		var retryable bool
		accepted, retryable, err = sendReport(client, *base, source, *tenant, key, q, body)
		if err == nil {
			break
		}
		if !retryable || attempt >= *retries {
			return err
		}
		// Never less than a second: the v2 signature carries the time in whole seconds, and
		// one re-signed within the same second would be the same signature.
		time.Sleep(time.Duration(1<<min(attempt, 3)) * time.Second)
	}
	fmt.Fprintf(stdout, "ingested %s: %d event(s) accepted", source, accepted.Events)
	if accepted.Batch != "" {
		fmt.Fprintf(stdout, " (batch %s)", accepted.Batch)
	}
	fmt.Fprintln(stdout)

	if !*wait {
		return nil
	}
	if accepted.Batch == "" {
		return errors.New("-wait: this engine does not report batches, so there is nothing to wait for")
	}
	applied, done, err := waitForBatch(client, *api, *token, accepted.Batch, deadlineFrom(*timeout), 2*time.Second)
	if err != nil {
		return fmt.Errorf("-wait: %w", err)
	}
	if !done {
		return fmt.Errorf("-wait: batch %s not applied within %s", accepted.Batch, *timeout)
	}
	fmt.Fprintf(stdout, "applied to the graph at %s\n", applied.UTC().Format(time.RFC3339))
	return nil
}

type ingestReply struct {
	Events int    `json:"accepted_events"`
	Batch  string `json:"batch"`
}

// ingestSecret is the flag, else INGEST_HMAC_SECRET, else the file INGEST_HMAC_SECRET_FILE
// names - the server's own convention for keeping a secret out of the environment. A file
// that is named but cannot be read is an error, not an unsigned request.
func ingestSecret(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if v := os.Getenv("INGEST_HMAC_SECRET"); v != "" {
		return v, nil
	}
	if p := os.Getenv("INGEST_HMAC_SECRET_FILE"); p != "" {
		b, err := os.ReadFile(p) // #nosec G304 G703 -- operator-supplied path to their own secret
		if err != nil {
			return "", fmt.Errorf("INGEST_HMAC_SECRET_FILE: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return "", nil
}

// readReport reads the report whole - it is signed whole - and refuses one the endpoint
// would refuse anyway, before sending it.
func readReport(path string, stdin io.Reader) ([]byte, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path) // #nosec G304 G703 -- operator-supplied path to their own scanner output
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	body, err := io.ReadAll(io.LimitReader(r, ingestion.MaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > ingestion.MaxBody {
		return nil, fmt.Errorf("%s is larger than the %d MiB the ingestion endpoint accepts", path, ingestion.MaxBody>>20)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return body, nil
}

// sendReport makes one attempt. retryable says whether another could succeed: a network
// error, a 429 or a 5xx may pass; a refused signature, an unknown collector or a report the
// collector cannot parse will not.
func sendReport(client *http.Client, base, source, tenant, secret string, q url.Values, body []byte) (ingestReply, bool, error) {
	endpoint := strings.TrimSuffix(base, "/") + "/ingest/" + url.PathEscape(source)
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ingestReply{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if tenant != "" {
		req.Header.Set(auth.TenantHeader, tenant)
	}
	if secret != "" {
		ts := time.Now().Unix()
		req.Header.Set(auth.TimestampHeader, strconv.FormatInt(ts, 10))
		req.Header.Set(auth.SignatureV2Header, auth.SignV2(secret, ts, http.MethodPost, "/ingest/"+url.PathEscape(source), q, body))
	}

	resp, err := client.Do(req)
	if err != nil {
		return ingestReply{}, true, fmt.Errorf("POST /ingest/%s: %w", source, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 300 {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		msg := strings.TrimSpace(string(rb))
		if resp.StatusCode == http.StatusUnauthorized && secret == "" {
			msg += " - the endpoint requires a signature: set INGEST_HMAC_SECRET"
		}
		return ingestReply{}, retryable, fmt.Errorf("POST /ingest/%s returned %d: %s", source, resp.StatusCode, msg)
	}
	var out ingestReply
	_ = json.Unmarshal(rb, &out) // an older engine says less; what was accepted still was
	return out, false, nil
}
