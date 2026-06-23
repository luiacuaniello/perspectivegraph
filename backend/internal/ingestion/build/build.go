// Package build ingests CI build provenance: which repository a container
// image was built from. It is the collector that emits the
// Image --BUILT_FROM--> Repository edge, the link that makes SAST findings
// (Semgrep, attached to the Repository) reachable from runtime workloads
// (which HOST the Image) - without it, code findings float disconnected.
//
// A CI step posts it right after pushing the image:
//
//	curl -X POST $INGEST/ingest/build -d '{
//	  "image": "payments-api:1.4.2",
//	  "repository": "payments-api",
//	  "slug": "acme/payments-api",
//	  "sha": "deadbeef"
//	}'
//
// Accepts a single object or a JSON array of them.
package build

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type provenance struct {
	Image      string `json:"image"`      // image ref as scanners report it, e.g. "payments-api:1.4.2"
	Repository string `json:"repository"` // repo short name, e.g. "payments-api"
	Slug       string `json:"slug"`       // forge slug, e.g. "acme/payments-api"
	SHA        string `json:"sha"`        // built commit
}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "build" }

func (c *Collector) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	records, err := decode(r)
	if err != nil {
		return nil, err
	}

	var nodes []ontology.Node
	var edges []ontology.Edge
	for _, p := range records {
		if p.Slug == "" {
			p.Slug = opts.RepoSlug
		}
		if p.Image == "" || p.Repository == "" {
			return nil, fmt.Errorf("build provenance needs both image and repository (got image=%q repository=%q)", p.Image, p.Repository)
		}

		imgProps := map[string]any{"artifact_type": "container-image"}
		repoProps := map[string]any{}
		if p.Slug != "" {
			imgProps[ontology.PropRepoSlug] = p.Slug
			repoProps[ontology.PropRepoSlug] = p.Slug
		}
		if p.SHA != "" {
			imgProps[ontology.PropCommitSHA] = p.SHA
		}

		imgID := ontology.NewID(ontology.LabelImage, p.Image)
		repoID := ontology.NewID(ontology.LabelRepository, p.Repository)
		nodes = append(nodes,
			ontology.Node{ID: imgID, Label: ontology.LabelImage, Name: p.Image, Properties: imgProps},
			ontology.Node{ID: repoID, Label: ontology.LabelRepository, Name: p.Repository, Properties: repoProps},
		)
		edges = append(edges, ontology.Edge{
			Type: ontology.EdgeBuiltFrom, From: imgID, To: repoID, ExploitProbability: 0.9,
		})
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      nodes,
		Edges:      edges,
	}}, nil
}

func decode(r io.Reader) ([]provenance, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	for _, c := range data {
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			continue
		}
		if c == '[' {
			var arr []provenance
			if err := json.Unmarshal(data, &arr); err != nil {
				return nil, fmt.Errorf("decode build provenance array: %w", err)
			}
			return arr, nil
		}
		break
	}
	var one provenance
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, fmt.Errorf("decode build provenance: %w", err)
	}
	return []provenance{one}, nil
}
