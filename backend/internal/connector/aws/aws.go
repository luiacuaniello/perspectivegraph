// Package aws is the AWS agentless connector. It pulls the read-only describe-*
// state from an AWS account and turns it into the same events the file-upload
// path produces - by reusing the existing cloudnet and iam collectors verbatim.
//
// The acquisition is abstracted behind a transport so the architecture is
// provable without credentials: the `fixtures` transport reads local describe-*
// JSON (demo/test), while the `sdk` transport calls AWS via aws-sdk-go-v2. Both
// hand the exact same JSON to the collectors, so everything downstream - identity
// resolution, the graph, the analyzer - is unchanged.
package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Feed names a unit of AWS state and the collector shape it must arrive in.
type Feed string

const (
	// FeedNetwork is the cloudnet bundle: ec2 describe-security-groups +
	// describe-instances + describe-vpc-peering-connections.
	FeedNetwork Feed = "cloudnet"
	// FeedIAM is iam get-account-authorization-details.
	FeedIAM Feed = "iam"
)

// transport acquires the raw describe-* JSON the existing collectors parse.
type transport interface {
	// Mode is a short label for logs/status, e.g. "fixtures" or "sdk".
	Mode() string
	// Fetch returns the raw JSON for one feed, or (nil, nil) when that feed is
	// not configured for this transport (so an account with no IAM access can
	// still pull the network feed).
	Fetch(ctx context.Context, feed Feed) ([]byte, error)
}

// Connector is the AWS agentless connector.
type Connector struct {
	t     transport
	feeds []feedBinding
}

type feedBinding struct {
	feed Feed
	col  ingestion.Collector // the existing collector that parses this feed
}

// New builds the AWS connector over a transport (Fixtures or SDK). The feed→
// collector bindings are the whole point: the connector itself parses nothing,
// it routes each feed to the collector that already understands it.
func New(t transport) *Connector {
	return &Connector{
		t: t,
		feeds: []feedBinding{
			{FeedNetwork, cloudnet.New()},
			{FeedIAM, iam.New()},
		},
	}
}

// Mode exposes the transport mode for logging.
func (c *Connector) Mode() string { return c.t.Mode() }

// Source identifies the connector.
func (*Connector) Source() string { return "aws" }

// Collect pulls every feed and parses it through its collector. A feed that
// fails (or is absent) doesn't sink the others: its error is joined and the
// remaining events are still returned, so a partial pull degrades gracefully.
func (c *Connector) Collect(ctx context.Context) ([]ontology.Event, error) {
	var out []ontology.Event
	var errs []error
	for _, b := range c.feeds {
		raw, err := c.t.Fetch(ctx, b.feed)
		if err != nil {
			errs = append(errs, fmt.Errorf("fetch %s: %w", b.feed, err))
			continue
		}
		if len(raw) == 0 {
			continue // feed not configured for this transport
		}
		evs, err := b.col.Parse(bytes.NewReader(raw), ingestion.Options{})
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s: %w", b.feed, err))
			continue
		}
		out = append(out, evs...)
	}
	return out, errors.Join(errs...)
}
