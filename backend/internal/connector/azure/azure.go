// Package azure is the Azure agentless connector. It pulls read-only Azure state
// and turns it into the same events the file-upload path produces - by mapping it
// onto the shape the existing cloudnet collector already parses, then reusing that
// collector verbatim. So identity resolution, the graph, and the analyzer run
// unchanged; only the acquisition is new.
//
// Unlike AWS (whose describe-* JSON IS the collector shape), Azure's native model
// differs, so each feed is mapped first (see mapper.go). The acquisition is behind
// a transport so the architecture is provable without credentials: the `fixtures`
// transport reads normalized Azure JSON from disk (demo/test) - the same shape a
// small `az ... -o json` slice produces - while a live SDK transport is the wired
// extension point.
package azure

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Feed names a unit of Azure state and the collector shape it must be mapped into.
type Feed string

// FeedNetwork is the VNet/NSG/VM/peering bundle, mapped to the cloudnet shape.
const FeedNetwork Feed = "network"

// transport acquires the raw normalized Azure JSON for a feed.
type transport interface {
	// Mode is a short label for logs/status, e.g. "fixtures".
	Mode() string
	// Fetch returns the raw Azure JSON for one feed, or (nil, nil) when that feed
	// is not configured (so a subscription with only network state still pulls).
	Fetch(ctx context.Context, feed Feed) ([]byte, error)
}

// Connector is the Azure agentless connector.
type Connector struct {
	t     transport
	feeds []feedBinding
}

type feedBinding struct {
	feed   Feed
	mapper func([]byte) ([]byte, error) // Azure JSON -> collector-shaped JSON
	col    ingestion.Collector          // the existing collector that parses the mapped shape
}

// New builds the Azure connector over a transport (Fixtures or a live SDK). Each
// feed is bound to a mapper (Azure -> collector shape) and the collector that then
// parses it; the connector itself only routes, so downstream is unchanged.
func New(t transport) *Connector {
	return &Connector{
		t: t,
		feeds: []feedBinding{
			{FeedNetwork, mapNetworkToCloudnet, cloudnet.New()},
		},
	}
}

// Mode exposes the transport mode for logging.
func (c *Connector) Mode() string { return c.t.Mode() }

// Source identifies the connector.
func (*Connector) Source() string { return "azure" }

// Collect pulls every feed, maps it to its collector's shape, and parses it. A
// feed that fails (or is absent) doesn't sink the others: its error is joined and
// the remaining events are still returned, so a partial pull degrades gracefully.
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
		mapped, err := b.mapper(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("map %s: %w", b.feed, err))
			continue
		}
		evs, err := b.col.Parse(bytes.NewReader(mapped), ingestion.Options{})
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s: %w", b.feed, err))
			continue
		}
		out = append(out, evs...)
	}
	return out, errors.Join(errs...)
}
