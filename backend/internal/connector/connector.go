// Package connector is the agentless, PULL side of ingestion.
//
// internal/ingestion receives PUSHED scanner output (a webhook posts a Trivy or
// Macie report). A Connector inverts that: it reaches OUT to an external system
// — a cloud account, an IdP, a code host — on a schedule and returns the events
// it finds, with no agent to deploy and no one to remember to upload a file.
//
// Crucially a connector emits the *same* normalized ontology.Event stream onto
// the *same* bus, so it reuses the entire downstream pipeline unchanged:
// identity resolution, the graph upsert, the analyzer. Only the acquisition is
// new. The AWS connector, for instance, simply pulls the describe-* JSON that
// the existing cloudnet/iam collectors already know how to parse.
package connector

import (
	"context"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Connector is one agentless source.
type Connector interface {
	// Source identifies the connector, e.g. "aws". Stamped for metrics/logs and
	// connector status; the events it emits keep their own collector source.
	Source() string

	// Collect pulls the current state from the external system and returns the
	// events describing it. It MUST be safe to call repeatedly: the graph upsert
	// and last_seen stamping make re-collection a refresh, not a duplication. It
	// MUST respect ctx for cancellation/timeout, and should return as many events
	// as it can even if one sub-feed fails (joining the errors), so a single bad
	// API call doesn't blank out the whole pull.
	Collect(ctx context.Context) ([]ontology.Event, error)
}
