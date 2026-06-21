// Package trivy converts an Aqua Trivy JSON report into ontology events.
//
// Edge orientation note: AegisGraph orients edges in the direction of attack
// *progression* (asset → vulnerability), so an attacker who reaches an image
// reaches its libraries, and from a library reaches the CVEs it exposes. This
// keeps Dijkstra traversal (internet → crown jewel) natural while still using
// the ontology's AFFECTS / DEPENDS_ON edge types.
package trivy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aegisgraph/aegisgraph/internal/ingestion"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

// report is the subset of the Trivy schema we consume.
type report struct {
	ArtifactName string `json:"ArtifactName"`
	ArtifactType string `json:"ArtifactType"`
	Results      []struct {
		Target          string `json:"Target"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "trivy" }

func (c *Collector) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	var rep report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode trivy report: %w", err)
	}
	if rep.ArtifactName == "" {
		return nil, fmt.Errorf("trivy report missing ArtifactName")
	}

	imageID := ontology.NewID(ontology.LabelImage, rep.ArtifactName)
	imageProps := map[string]any{"artifact_type": rep.ArtifactType}
	for k, v := range opts.PRProps() { // PR context for the action layer
		imageProps[k] = v
	}
	image := ontology.Node{
		ID:         imageID,
		Label:      ontology.LabelImage,
		Name:       rep.ArtifactName,
		Properties: imageProps,
	}

	nodes := []ontology.Node{image}
	var edges []ontology.Edge
	seenLib := map[string]bool{}
	seenCVE := map[string]bool{}

	for _, res := range rep.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" || v.PkgName == "" {
				continue
			}

			libID := ontology.NewID(ontology.LabelLibrary, v.PkgName, v.InstalledVersion)
			if !seenLib[libID] {
				seenLib[libID] = true
				nodes = append(nodes, ontology.Node{
					ID:    libID,
					Label: ontology.LabelLibrary,
					Name:  fmt.Sprintf("%s@%s", v.PkgName, v.InstalledVersion),
					Properties: map[string]any{
						"ecosystem": res.Type,
						"version":   v.InstalledVersion,
					},
				})
				// Image depends on the library (attacker on image reaches lib).
				edges = append(edges, ontology.Edge{
					Type:               ontology.EdgeDependsOn,
					From:               imageID,
					To:                 libID,
					ExploitProbability: 0.95,
				})
			}

			cveID := ontology.NewID(ontology.LabelCVE, v.VulnerabilityID)
			if !seenCVE[cveID] {
				seenCVE[cveID] = true
				nodes = append(nodes, ontology.Node{
					ID:    cveID,
					Label: ontology.LabelCVE,
					Name:  v.VulnerabilityID,
					Properties: map[string]any{
						ontology.PropSeverity: strings.ToUpper(v.Severity),
						ontology.PropCVSS:     cvssScore(v.CVSS),
						"fixed_version":       v.FixedVersion,
						"title":               v.Title,
					},
				})
			}
			// Library exposes (is affected by) the CVE.
			edges = append(edges, ontology.Edge{
				Type:               ontology.EdgeAffects,
				From:               libID,
				To:                 cveID,
				ExploitProbability: severityProbability(v.Severity),
			})
		}
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindFinding,
		ObservedAt: time.Now().UTC(),
		Nodes:      nodes,
		Edges:      edges,
	}}, nil
}

// severityProbability maps Trivy severity to an exploit probability for the
// AFFECTS edge. Higher severity => more likely an attacker leverages it.
func severityProbability(sev string) float64 {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 0.9
	case "HIGH":
		return 0.7
	case "MEDIUM":
		return 0.4
	case "LOW":
		return 0.2
	default:
		return 0.1
	}
}

// cvssScore returns the highest V3 base score across reporting sources.
func cvssScore(sources map[string]struct {
	V3Score float64 `json:"V3Score"`
}) float64 {
	var max float64
	for _, s := range sources {
		if s.V3Score > max {
			max = s.V3Score
		}
	}
	return max
}
