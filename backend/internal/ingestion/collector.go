// Package ingestion is the entry point for external scanner output. Each
// supported tool has a Collector that parses its native format into normalized
// ontology.Events. A small HTTP server (server.go) receives webhooks/uploads
// and publishes the resulting events onto the bus.
package ingestion

import (
	"io"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Options carries per-request context a collector may need when the tool's own
// output doesn't self-identify the scanned asset. Sourced from query params on
// the ingest webhook, e.g.
//
//	POST /ingest/semgrep?repo=payments-api&slug=acme/payments-api&pr=42&sha=abc123
type Options struct {
	// Repository is the repo a report pertains to. Semgrep output, for
	// instance, contains file paths but not the repository identity.
	Repository string

	// Pull-request context, set by CI when scanning a PR. When present,
	// collectors stamp it onto their primary asset node so the action layer
	// can comment on the originating pull request.
	RepoSlug  string // "owner/name"
	PRNumber  int
	CommitSHA string
}

// PRProps returns the PR-context node properties carried by these options, or
// nil when there is no PR context. Collectors merge this into their primary
// asset node (the Repository for SAST, the Image for container scans).
func (o Options) PRProps() map[string]any {
	if o.RepoSlug == "" && o.PRNumber == 0 && o.CommitSHA == "" {
		return nil
	}
	p := map[string]any{}
	if o.RepoSlug != "" {
		p[ontology.PropRepoSlug] = o.RepoSlug
	}
	if o.PRNumber > 0 {
		p[ontology.PropPRNumber] = o.PRNumber
	}
	if o.CommitSHA != "" {
		p[ontology.PropCommitSHA] = o.CommitSHA
	}
	return p
}

// Collector parses one tool's output into normalized events.
type Collector interface {
	// Source is the tool identifier, e.g. "trivy". Used as the bus subject
	// suffix and the Event.Source field.
	Source() string
	// Parse reads a single report and returns the events it describes.
	Parse(r io.Reader, opts Options) ([]ontology.Event, error)
}
