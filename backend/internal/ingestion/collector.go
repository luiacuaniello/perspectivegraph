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

	// Account is the cloud account the report describes, for sources whose output
	// carries native identifiers (i-…, sg-…) that are unique only within one account.
	// Empty keeps the pre-multi-account behaviour, so an estate that ingests from a
	// single account is unaffected by this existing at all.
	Account string

	// Cluster is the Kubernetes cluster a dump describes. Names in a cluster are unique only
	// within it - every cluster has a prod namespace, a default ServiceAccount and a
	// cluster-admin - so dumps of two clusters sent without it describe one imaginary
	// cluster, and a route can start in one and end in the other. Empty keeps the ids a
	// single-cluster estate always had.
	Cluster string

	// EstateKnown says the report is read against an estate that already describes the
	// deployed assets - an engine's graph, or a live read of the account. A change report
	// then leaves to the estate what it cannot judge better: a Terraform plan whose
	// configuration does not describe a subnet's routing says nothing about an untouched
	// instance's exposure that the account itself does not say more precisely.
	EstateKnown bool

	// LiveNetwork is the account's network as a live read fetched it: the cloudnet feed's
	// bundle (describe-security-groups, describe-instances, routes, network ACLs…). A
	// change report lays its own network over it, so that a rule it adds to a group meets
	// the instances elsewhere that use the group, and an instance it puts in a group meets
	// the group's rules. Empty without a live read; the graph does not hold either.
	LiveNetwork []byte
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

// ChangeParser is a collector for a report that describes a change before it is made: a
// Terraform plan. Besides the state the change leads to - what Parse returns - it says
// which state the change starts from, and what cannot be known until it is applied.
//
// The gate takes Before as part of the estate. A plan describes the resources it manages
// as they are now, and the comparison has to start from that description, not only from
// whatever the estate holds: an asset read two ways - from the cloud's API, and from the
// plan - would otherwise differ between the two sides for no reason the change gives.
//
// Such a report is the gate's alone. It describes what is not deployed yet, so the ingest
// webhook refuses it rather than write a planned state into the live graph.
type ChangeParser interface {
	Collector
	ParseChange(r io.Reader, opts Options) (Change, error)
}

// Change is a change report, parsed.
type Change struct {
	Before, After []ontology.Event
	// Unknown lists what the change leaves unknown until it is applied - a policy that
	// names a resource not created yet. A route through any of it can be neither found
	// nor ruled out, so a comparison that finds none is not clean but unknown.
	Unknown []string
	// Outside lists what the change reaches but neither it nor the estate describes - a
	// security group it opens that instances it does not describe may use. Like Unknown, a
	// route through it can be neither found nor ruled out.
	Outside []string
}
