package trivy

import (
	"encoding/json"
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
// must be well-formed (non-empty ids, ontology-valid labels/types) - otherwise a
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
			return // a rejected report is a fine outcome - just no panic
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

// imageFrom parses a one-vulnerability report and returns its Image node, which is all
// the naming tests look at.
func imageFrom(t *testing.T, artifactName, artifactType, metadata string) ontology.Node {
	t.Helper()
	doc := `{"ArtifactName": ` + strconvQuote(artifactName) + `, "ArtifactType": ` + strconvQuote(artifactType) +
		`, "Metadata": ` + metadata + `, "Results": [{"Target": "app", "Type": "jar", "Vulnerabilities": [
		{"VulnerabilityID": "CVE-2021-44228", "PkgName": "log4j-core", "InstalledVersion": "2.14.1", "Severity": "CRITICAL"}]}]}`
	events, err := New().Parse(strings.NewReader(doc), ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, n := range events[0].Nodes {
		if n.Label == ontology.LabelImage {
			return n
		}
	}
	t.Fatal("no image node")
	return ontology.Node{}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// The name an image is joined on. An archive scan reports the FILE PATH as ArtifactName,
// which joins no workload; the saved tag is recovered from Metadata instead - but only
// ever in place of a path, never in place of a name somebody scanned by.
func TestImageNameForArchiveScans(t *testing.T) {
	const tagged = `{"Reference": "payments-api:1.0.0", "RepoTags": ["payments-api:1.0.0"]}`
	for _, tc := range []struct {
		name, artifact, artifactType, metadata string
		want, source                           string
		archive, note                          bool
	}{
		// Exactly what `trivy image --input /work/image.tar` wrote for a `docker save` tarball.
		{"docker-save archive", "/work/image.tar", "container_image", tagged, "payments-api:1.0.0", "Metadata.Reference", true, false},
		{"relative archive", "image.tar", "container_image", tagged, "payments-api:1.0.0", "Metadata.Reference", true, false},
		{"compressed archive", "./out/image.tar.gz", "container_image", tagged, "payments-api:1.0.0", "Metadata.Reference", true, false},
		{"windows path", `C:\ci\image.tar`, "container_image", tagged, "payments-api:1.0.0", "Metadata.Reference", true, false},
		{"tags but no reference", "/work/image.tar", "container_image", `{"RepoTags": ["payments-api:1.0.0"]}`, "payments-api:1.0.0", "Metadata.RepoTags", true, false},
		// Saved by image ID: nothing names it. Kept under the path, and flagged.
		{"untagged archive", "/work/image.tar", "container_image", `{}`, "/work/image.tar", "", true, true},
		// Scanned by name: the name is the join key and must not move, even though Trivy
		// normalises the Reference to something else.
		{"scanned by reference", "nginx", "container_image", `{"Reference": "nginx:latest", "RepoTags": ["nginx:latest"]}`, "nginx", "", false, false},
		{"registry reference", "ghcr.io/acme/app:2.0", "container_image", tagged, "ghcr.io/acme/app:2.0", "", false, false},
		// Not an image at all: a filesystem scan's ArtifactName is a path by design.
		{"filesystem scan", ".", "filesystem", `{}`, ".", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := imageFrom(t, tc.artifact, tc.artifactType, tc.metadata)
			if img.Name != tc.want {
				t.Errorf("image named %q, want %q", img.Name, tc.want)
			}
			if img.ID != ontology.NewID(ontology.LabelImage, tc.want) {
				t.Errorf("the id is not derived from the name, so the join would still miss")
			}
			if got, _ := img.Properties["name_source"].(string); got != tc.source {
				t.Errorf("name_source = %q, want %q", got, tc.source)
			}
			if _, ok := img.Properties["scanned_archive"]; ok != tc.archive {
				t.Errorf("scanned_archive present = %v, want %v", ok, tc.archive)
			}
			if _, ok := img.Properties["name_note"]; ok != tc.note {
				t.Errorf("name_note present = %v, want %v", ok, tc.note)
			}
		})
	}
}
