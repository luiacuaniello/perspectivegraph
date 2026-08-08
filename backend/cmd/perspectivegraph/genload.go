package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"

	"github.com/luiacuaniello/perspectivegraph/internal/synthgraph"
)

// runGenload builds a layered synthetic attack surface and POSTs it as one ingest
// event, so an operator can exercise the analyzer's scaling on a running stack
// without wiring up real scanners:
//
//	perspectivegraph genload --seeds 64 --layers 10 --width 1000 --fanout 5
//
// The graph is a DAG of `layers` ranks of `width` nodes; each node fans out to
// `fanout` nodes in the next rank with a pseudo-random exploit probability. The
// first `seeds` rank-0 nodes are internet-exposed; the last `jewels` final-rank
// nodes are crown jewels - so the analyzer finds seeds×jewels candidate routes.
func runGenload(args []string) error {
	fs := flag.NewFlagSet("genload", flag.ContinueOnError)
	url := fs.String("url", "http://localhost:8081/ingest/events", "ingest events endpoint")
	seeds := fs.Int("seeds", 32, "internet-exposed seed nodes (rank 0)")
	jewels := fs.Int("jewels", 16, "crown-jewel target nodes (final rank)")
	layers := fs.Int("layers", 8, "graph depth (number of ranks)")
	width := fs.Int("width", 500, "nodes per rank")
	fanout := fs.Int("fanout", 4, "forward edges per node")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token, if ingest auth is on")
	randSeed := fs.Int64("rand", 42, "PRNG seed (reproducible graphs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *seeds < 1 || *jewels < 1 || *layers < 2 || *width < 1 || *fanout < 1 {
		return fmt.Errorf("seeds/jewels/width/fanout must be ≥1 and layers ≥2")
	}
	if *seeds > *width || *jewels > *width {
		return fmt.Errorf("seeds and jewels must each be ≤ width (%d)", *width)
	}

	nodes, edges := synthgraph.Build(*seeds, *jewels, *layers, *width, *fanout, *randSeed)
	// One event is published as one NATS message, so chunk well under the broker's
	// default 1 MiB max_payload. Nodes go first (in order) so an edge's endpoints
	// exist by the time it is consumed (JetStream preserves per-subject order; the
	// broker also redelivers an edge whose endpoints aren't in yet).
	const nodesPerEvent, edgesPerEvent = 1500, 3000
	var events []ontology.Event
	now := time.Now()
	for i := 0; i < len(nodes); i += nodesPerEvent {
		events = append(events, ontology.Event{Source: "genload", Kind: ontology.KindAsset,
			ObservedAt: now, Nodes: nodes[i:min(i+nodesPerEvent, len(nodes))]})
	}
	for i := 0; i < len(edges); i += edgesPerEvent {
		events = append(events, ontology.Event{Source: "genload", Kind: ontology.KindRelationship,
			ObservedAt: now, Edges: edges[i:min(i+edgesPerEvent, len(edges))]})
	}

	body, err := json.Marshal(events)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, *url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ingest returned %s", resp.Status)
	}
	fmt.Printf("genload: posted %d nodes + %d edges in %d events (%d KiB) → %s [%s]\n",
		len(nodes), len(edges), len(events), len(body)/1024, *url, resp.Status)
	fmt.Printf("  give the analyzer a pass, then query: { status { passes } attackPaths(limit:5){ id score } }\n")
	return nil
}
