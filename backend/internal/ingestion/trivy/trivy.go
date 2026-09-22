// Package trivy converts an Aqua Trivy JSON report into ontology events.
//
// Edge orientation note: PerspectiveGraph orients edges in the direction of attack
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

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// report is the subset of the Trivy schema we consume.
type report struct {
	ArtifactName string `json:"ArtifactName"`
	ArtifactType string `json:"ArtifactType"`
	// Metadata carries the image's own reference, which is what names it when
	// ArtifactName does not - see imageName.
	Metadata struct {
		Reference string   `json:"Reference"`
		RepoTags  []string `json:"RepoTags"`
	} `json:"Metadata"`
	Results []struct {
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

	imageProps := map[string]any{"artifact_type": rep.ArtifactType}
	name := imageName(rep, imageProps)
	imageID := ontology.NewID(ontology.LabelImage, name)
	for k, v := range opts.PRProps() { // PR context for the action layer
		imageProps[k] = v
	}
	image := ontology.Node{
		ID:         imageID,
		Label:      ontology.LabelImage,
		Name:       name,
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

// imageName is the name the scanned image is known by in the estate: the key a running
// workload is joined to it on.
//
// Usually that is ArtifactName. Scanning an archive - `trivy image --input image.tar`,
// the usual way to scan in CI without a Docker daemon - makes ArtifactName the FILE PATH
// instead, and a path matches no workload. The libraries and CVEs then arrive joined to
// nothing, and a gate reading the report answers CLEAN for a commit it never connected
// to anything: a false negative that looks exactly like a pass. Trivy still records the
// tag the archive was saved with, in Metadata.Reference and RepoTags, so the name is
// recoverable.
//
// It is recovered only in place of a path, never in place of a name somebody scanned
// by: `trivy image nginx` reports Reference "nginx:latest", and a workload that runs
// "nginx" must keep joining the image it always joined. What was substituted is recorded
// on the node, so the graph shows where the name came from.
func imageName(rep report, props map[string]any) string {
	if rep.ArtifactType != "container_image" || !isArchivePath(rep.ArtifactName) {
		return rep.ArtifactName
	}
	props["scanned_archive"] = rep.ArtifactName
	if ref := rep.Metadata.Reference; ref != "" && !isArchivePath(ref) {
		props["name_source"] = "Metadata.Reference"
		return ref
	}
	for _, tag := range rep.Metadata.RepoTags {
		if tag != "" {
			props["name_source"] = "Metadata.RepoTags"
			return tag
		}
	}
	// An archive saved by image ID carries no tag at all. Nothing in the report says which
	// workload runs it, so it is kept under its path - and says so, rather than passing
	// for an image that was looked at and found unreachable.
	props["name_note"] = "scanned from an archive saved without an image tag, so nothing says which workload runs it " +
		"and it cannot join the estate; save it with a tag (docker save name:tag) or scan the image by reference"
	return rep.ArtifactName
}

// isArchivePath reports whether an ArtifactName is a filesystem path rather than an
// image reference. A reference always starts with a letter or digit, so a leading "/",
// "." or "~" - or a Windows separator - is a path; so is an archive extension, which
// covers a relative "image.tar".
func isArchivePath(name string) bool {
	if name == "" {
		return false
	}
	if strings.ContainsAny(name[:1], "/.~") || strings.Contains(name, `\`) {
		return true
	}
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz")
}

// severityProbability maps Trivy severity to an exploit probability for the
// AFFECTS edge via the shared cross-collector scale.
func severityProbability(sev string) float64 {
	return ingestion.SeverityProbability(sev)
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
