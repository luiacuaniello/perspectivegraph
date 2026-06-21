package supplychain

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func parse(t *testing.T, in string) ontology.Event {
	t.Helper()
	events, err := New().Parse(strings.NewReader(in), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return events[0]
}

func TestStampsTrustAndSBOM(t *testing.T) {
	ev := parse(t, `{
	  "image":"payments-api:1.4.2","signed":false,"slsa_level":2,
	  "provenance_builder":"github-actions","source_repo":"payments-api",
	  "sbom":[{"name":"log4j-core","version":"2.14.1","type":"library"},
	          {"name":"openssl","version":"3.0.0","type":"application"}]
	}`)

	imgID := ontology.NewID(ontology.LabelImage, "payments-api:1.4.2")
	var img *ontology.Node
	libs, pkgs, depends, builtFrom := 0, 0, 0, 0
	for i := range ev.Nodes {
		n := &ev.Nodes[i]
		switch {
		case n.ID == imgID:
			img = n
		case n.Label == ontology.LabelLibrary:
			libs++
		case n.Label == ontology.LabelPackage:
			pkgs++
		}
	}
	for _, e := range ev.Edges {
		switch e.Type {
		case ontology.EdgeDependsOn:
			depends++
		case ontology.EdgeBuiltFrom:
			builtFrom++
		}
	}
	if img == nil {
		t.Fatal("missing image node")
	}
	if signed, ok := img.Properties[ontology.PropSigned].(bool); !ok || signed {
		t.Errorf("image should be assessed unsigned, got %v ok=%v", signed, ok)
	}
	if lvl, _ := img.Properties[ontology.PropSLSALevel].(int); lvl != 2 {
		t.Errorf("slsa_level = %v, want 2", img.Properties[ontology.PropSLSALevel])
	}
	if n, _ := img.Properties[ontology.PropSBOMComponents].(int); n != 2 {
		t.Errorf("sbom_components = %v, want 2", img.Properties[ontology.PropSBOMComponents])
	}
	if libs != 1 || pkgs != 1 {
		t.Errorf("want 1 library + 1 package, got %d libs %d pkgs", libs, pkgs)
	}
	if depends != 2 {
		t.Errorf("want 2 DEPENDS_ON edges, got %d", depends)
	}
	if builtFrom != 1 {
		t.Errorf("want 1 BUILT_FROM edge, got %d", builtFrom)
	}
	// The SBOM library must converge with the same id Trivy uses for it.
	if want := ontology.NewID(ontology.LabelLibrary, "log4j-core:2.14.1"); !hasNode(ev.Nodes, want) {
		t.Errorf("library node id should key on name:version (%s)", want)
	}
}

// A signed image must record signed=true (assessed), distinct from "unknown".
func TestSignedTrueIsRecorded(t *testing.T) {
	ev := parse(t, `{"image":"a:1","signed":true}`)
	img := ev.Nodes[0]
	if signed, ok := img.Properties[ontology.PropSigned].(bool); !ok || !signed {
		t.Errorf("signed image should record signed=true, got %v ok=%v", signed, ok)
	}
}

// "Never assessed" (signed omitted) must NOT stamp PropSigned, so the policy
// invariant can tell unknown apart from unsigned.
func TestUnassessedLeavesSignedAbsent(t *testing.T) {
	ev := parse(t, `{"image":"a:1"}`)
	if _, present := ev.Nodes[0].Properties[ontology.PropSigned]; present {
		t.Error("an unassessed image must not carry a signed property")
	}
}

// A CycloneDX document is accepted directly (real syft/trivy output).
func TestAcceptsCycloneDX(t *testing.T) {
	ev := parse(t, `{"image":"a:1","sbom":{"bomFormat":"CycloneDX","components":[
	  {"name":"log4j-core","version":"2.14.1","type":"library","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}}`)
	got, _ := ev.Nodes[0].Properties[ontology.PropSBOMComponents].(int)
	if got != 1 {
		t.Fatalf("CycloneDX components not parsed: sbom_components=%v", ev.Nodes[0].Properties[ontology.PropSBOMComponents])
	}
}

func hasNode(nodes []ontology.Node, id string) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}
