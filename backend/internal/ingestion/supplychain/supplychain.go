// Package supplychain ingests software supply-chain provenance for a container
// image: its signature (cosign), its build attestation (SLSA), and its bill of
// materials (SBOM). It is the layer that lets PerspectiveGraph reason about a
// modern supply-chain attack - a tampered or unsigned image that runs in prod
// and reaches a crown jewel - not just CVEs in known dependencies.
//
// It is a sibling of the build collector and stamps the *same* Image node with
// trust signals (signed / slsa_level / provenance_builder) and a DEPENDS_ON edge
// to each SBOM component, so the dependency inventory is complete and queryable.
//
// A CI step posts it after signing/attesting the image, e.g. assembled from
// `cosign verify`, `cosign verify-attestation --type slsaprovenance`, and
// `syft <image> -o cyclonedx-json`:
//
//	curl -X POST $INGEST/ingest/supplychain -d '{
//	  "image": "payments-api:1.4.2", "signed": false, "slsa_level": 0,
//	  "source_repo": "payments-api",
//	  "sbom": [{"name":"log4j-core","version":"2.14.1","type":"library"}]
//	}'
//
// `sbom` accepts either a plain component list or a CycloneDX document (the
// format `syft`/`trivy` emit), so real tool output drops in with no reshaping.
// Accepts a single object or a JSON array of them.
package supplychain

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type attestation struct {
	Image             string          `json:"image"`
	Signed            *bool           `json:"signed"`             // pointer: nil = not assessed
	SLSALevel         int             `json:"slsa_level"`         // 0..4
	ProvenanceBuilder string          `json:"provenance_builder"` // e.g. "github-actions"
	SourceRepo        string          `json:"source_repo"`        // repo short name (reuses BUILT_FROM)
	Slug              string          `json:"slug"`               // forge slug
	SBOM              json.RawMessage `json:"sbom"`               // []component OR a CycloneDX doc
}

type component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // "library" | "application" | …
	PURL    string `json:"purl"`
}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "supplychain" }

func (c *Collector) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	records, err := decode(r)
	if err != nil {
		return nil, err
	}

	var nodes []ontology.Node
	var edges []ontology.Edge
	for _, a := range records {
		if a.Image == "" {
			return nil, fmt.Errorf("supply-chain record needs an image ref")
		}
		comps, err := a.components()
		if err != nil {
			return nil, err
		}

		imgProps := map[string]any{"artifact_type": "container-image"}
		if a.Signed != nil {
			imgProps[ontology.PropSigned] = *a.Signed
		}
		if a.SLSALevel > 0 {
			imgProps[ontology.PropSLSALevel] = a.SLSALevel
		}
		if a.ProvenanceBuilder != "" {
			imgProps[ontology.PropProvenanceBuilder] = a.ProvenanceBuilder
		}
		if len(comps) > 0 {
			imgProps[ontology.PropSBOMComponents] = len(comps)
		}
		if slug := firstNonEmpty(a.Slug, opts.RepoSlug); slug != "" {
			imgProps[ontology.PropRepoSlug] = slug
		}

		imgID := ontology.NewID(ontology.LabelImage, a.Image)
		nodes = append(nodes, ontology.Node{
			ID: imgID, Label: ontology.LabelImage, Name: a.Image, Properties: imgProps,
		})

		// SBOM inventory: each component is a Library/Package the image DEPENDS_ON.
		// MERGE-keyed by name:version, so it converges with the same nodes Trivy
		// reports - SBOM adds the components that have no CVE, completing the bill.
		for _, comp := range comps {
			if comp.Name == "" {
				continue
			}
			label := ontology.LabelLibrary
			if comp.Type != "" && !strings.EqualFold(comp.Type, "library") {
				label = ontology.LabelPackage
			}
			key := comp.Name
			if comp.Version != "" {
				key = comp.Name + ":" + comp.Version
			}
			compID := ontology.NewID(label, key)
			name := comp.Name
			if comp.Version != "" {
				name = comp.Name + "@" + comp.Version
			}
			cprops := map[string]any{}
			if comp.PURL != "" {
				cprops["purl"] = comp.PURL
			}
			nodes = append(nodes, ontology.Node{ID: compID, Label: label, Name: name, Properties: cprops})
			edges = append(edges, ontology.Edge{
				Type: ontology.EdgeDependsOn, From: imgID, To: compID, ExploitProbability: 0.9,
			})
		}

		// Build provenance link (idempotent with the build collector's edge).
		if a.SourceRepo != "" {
			repoID := ontology.NewID(ontology.LabelRepository, a.SourceRepo)
			nodes = append(nodes, ontology.Node{ID: repoID, Label: ontology.LabelRepository, Name: a.SourceRepo})
			edges = append(edges, ontology.Edge{
				Type: ontology.EdgeBuiltFrom, From: imgID, To: repoID, ExploitProbability: 0.9,
			})
		}
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      nodes,
		Edges:      edges,
	}}, nil
}

// components normalizes the `sbom` field, which may be a plain list or a
// CycloneDX document, into a component slice.
func (a attestation) components() ([]component, error) {
	raw := []byte(strings.TrimSpace(string(a.SBOM)))
	if len(raw) == 0 {
		return nil, nil
	}
	switch raw[0] {
	case '[': // plain component list
		var list []component
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("decode sbom component list: %w", err)
		}
		return list, nil
	case '{': // CycloneDX document
		var cdx struct {
			Components []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
				PURL    string `json:"purl"`
			} `json:"components"`
		}
		if err := json.Unmarshal(raw, &cdx); err != nil {
			return nil, fmt.Errorf("decode CycloneDX sbom: %w", err)
		}
		out := make([]component, 0, len(cdx.Components))
		for _, c := range cdx.Components {
			out = append(out, component{Name: c.Name, Version: c.Version, Type: c.Type, PURL: c.PURL})
		}
		return out, nil
	}
	return nil, fmt.Errorf("sbom must be a component list or a CycloneDX document")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func decode(r io.Reader) ([]attestation, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	for _, c := range data {
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			continue
		}
		if c == '[' {
			var arr []attestation
			if err := json.Unmarshal(data, &arr); err != nil {
				return nil, fmt.Errorf("decode supply-chain array: %w", err)
			}
			return arr, nil
		}
		break
	}
	var one attestation
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, fmt.Errorf("decode supply-chain record: %w", err)
	}
	return []attestation{one}, nil
}
