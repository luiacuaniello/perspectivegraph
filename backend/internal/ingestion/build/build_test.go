package build

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestParseEmitsBuiltFrom(t *testing.T) {
	in := `{"image":"payments-api:1.4.2","repository":"payments-api","slug":"acme/payments-api","sha":"deadbeef"}`
	events, err := New().Parse(strings.NewReader(in), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ev := events[0]
	if len(ev.Nodes) != 2 || len(ev.Edges) != 1 {
		t.Fatalf("want 2 nodes + 1 edge, got %d nodes %d edges", len(ev.Nodes), len(ev.Edges))
	}
	e := ev.Edges[0]
	if e.Type != ontology.EdgeBuiltFrom {
		t.Errorf("edge type = %s, want BUILT_FROM", e.Type)
	}
	if e.From != ontology.NewID(ontology.LabelImage, "payments-api:1.4.2") ||
		e.To != ontology.NewID(ontology.LabelRepository, "payments-api") {
		t.Errorf("edge endpoints wrong: %s -> %s", e.From, e.To)
	}
	for _, n := range ev.Nodes {
		if got, _ := n.Properties[ontology.PropRepoSlug].(string); got != "acme/payments-api" {
			t.Errorf("node %s missing repo_slug: %v", n.Name, n.Properties)
		}
	}
}

func TestParseRejectsIncomplete(t *testing.T) {
	if _, err := New().Parse(strings.NewReader(`{"image":"x"}`), ingestion.Options{}); err == nil {
		t.Fatal("provenance without repository must be rejected")
	}
}
