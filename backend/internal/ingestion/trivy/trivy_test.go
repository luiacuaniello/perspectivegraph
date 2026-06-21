package trivy

import (
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// sample exercises dedup (a library and a CVE that recur across Results), the
// max-of-V3-scores CVSS pick, severity upper-casing, and the skip of incomplete
// vulnerabilities (missing VulnerabilityID/PkgName).
const sample = `{
  "ArtifactName": "acme/payments-api:1.4.2",
  "ArtifactType": "container_image",
  "Results": [
    {
      "Target": "app", "Type": "gobinary",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core",
          "InstalledVersion": "2.14.1", "FixedVersion": "2.15.0",
          "Severity": "critical", "Title": "Log4Shell",
          "CVSS": { "nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 10.0} }
        },
        {
          "VulnerabilityID": "CVE-2021-45046", "PkgName": "log4j-core",
          "InstalledVersion": "2.14.1", "Severity": "high",
          "CVSS": { "nvd": {"V3Score": 5.9} }
        }
      ]
    },
    {
      "Target": "app2", "Type": "gobinary",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core", "InstalledVersion": "2.14.1", "Severity": "critical" },
        { "VulnerabilityID": "", "PkgName": "skip-me" }
      ]
    }
  ]
}`

func countNodes(nodes []ontology.Node, label ontology.Label) int {
	n := 0
	for _, x := range nodes {
		if x.Label == label {
			n++
		}
	}
	return n
}

func countEdges(edges []ontology.Edge, t ontology.EdgeType) int {
	n := 0
	for _, e := range edges {
		if e.Type == t {
			n++
		}
	}
	return n
}

func TestParse(t *testing.T) {
	events, err := New().Parse(strings.NewReader(sample), ingestion.Options{
		RepoSlug: "acme/payments-api", PRNumber: 42, CommitSHA: "deadbeef",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Source != "trivy" || ev.Kind != ontology.KindFinding {
		t.Errorf("source/kind = %q/%q", ev.Source, ev.Kind)
	}

	// 1 image + 1 (deduped) library + 2 distinct CVEs.
	if got := countNodes(ev.Nodes, ontology.LabelImage); got != 1 {
		t.Errorf("image nodes = %d, want 1", got)
	}
	if got := countNodes(ev.Nodes, ontology.LabelLibrary); got != 1 {
		t.Errorf("library nodes = %d, want 1 (deduped across Results)", got)
	}
	if got := countNodes(ev.Nodes, ontology.LabelCVE); got != 2 {
		t.Errorf("CVE nodes = %d, want 2", got)
	}
	// DEPENDS_ON is emitted once per distinct library; AFFECTS once per vuln
	// (3 valid vulns; the empty-id one is skipped).
	if got := countEdges(ev.Edges, ontology.EdgeDependsOn); got != 1 {
		t.Errorf("DEPENDS_ON edges = %d, want 1", got)
	}
	if got := countEdges(ev.Edges, ontology.EdgeAffects); got != 3 {
		t.Errorf("AFFECTS edges = %d, want 3", got)
	}

	// The image carries its real name and the PR context for the action layer.
	var image ontology.Node
	for _, n := range ev.Nodes {
		if n.Label == ontology.LabelImage {
			image = n
		}
	}
	if image.Name != "acme/payments-api:1.4.2" {
		t.Errorf("image name = %q", image.Name)
	}
	if image.Properties[ontology.PropRepoSlug] != "acme/payments-api" {
		t.Errorf("image missing PR slug context: %v", image.Properties)
	}

	// CVE-2021-44228: severity upper-cased, CVSS = max V3 score (10.0).
	var log4shell ontology.Node
	for _, n := range ev.Nodes {
		if n.Name == "CVE-2021-44228" {
			log4shell = n
		}
	}
	if log4shell.Properties[ontology.PropSeverity] != "CRITICAL" {
		t.Errorf("severity = %v, want CRITICAL (upper-cased)", log4shell.Properties[ontology.PropSeverity])
	}
	if log4shell.Properties[ontology.PropCVSS] != 10.0 {
		t.Errorf("cvss = %v, want 10.0 (max across sources)", log4shell.Properties[ontology.PropCVSS])
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"empty body":           ``,
		"not json":             `<<not-json>>`,
		"missing ArtifactName": `{"Results": []}`,
		"truncated":            `{"ArtifactName": "x", "Results": [`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New().Parse(strings.NewReader(body), ingestion.Options{}); err == nil {
				t.Errorf("expected an error for %q, got nil", name)
			}
		})
	}
}

// FuzzParse asserts the contract every ingest parser must hold: it consumes
// untrusted webhook bytes, so it must NEVER panic, and any node/edge it emits
// must be well-formed (non-empty ids, ontology-valid labels/types) — otherwise a
// crafted report could crash the ingest goroutine or smuggle a malformed element
// toward the graph store.
func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add(``)
	f.Add(`{`)
	f.Add(`{"ArtifactName":"x"}`)
	f.Add(`{"ArtifactName":"x","Results":[{"Vulnerabilities":[{"VulnerabilityID":"C","PkgName":"p"}]}]}`)
	if b, err := os.ReadFile("../../../testdata/trivy-sample.json"); err == nil {
		f.Add(string(b))
	}

	c := New()
	f.Fuzz(func(t *testing.T, data string) {
		events, err := c.Parse(strings.NewReader(data), ingestion.Options{})
		if err != nil {
			return // a rejected report is a fine outcome — just no panic
		}
		for _, ev := range events {
			for _, n := range ev.Nodes {
				if n.ID == "" {
					t.Fatalf("emitted node with empty id: %+v", n)
				}
				if !ontology.IsValidLabel(n.Label) {
					t.Fatalf("emitted node with invalid label %q", n.Label)
				}
			}
			for _, e := range ev.Edges {
				if e.From == "" || e.To == "" {
					t.Fatalf("emitted edge with empty endpoint: %+v", e)
				}
				if !ontology.IsValidEdgeType(e.Type) {
					t.Fatalf("emitted edge with invalid type %q", e.Type)
				}
			}
		}
	})
}
