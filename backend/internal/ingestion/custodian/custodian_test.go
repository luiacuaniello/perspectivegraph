package custodian

import (
	"os"
	"testing"

	"github.com/aegisgraph/aegisgraph/internal/ingestion"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

func TestParseCloudScenario(t *testing.T) {
	f, err := os.Open("../../../testdata/custodian-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	events, err := New().Parse(f, ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]

	byLabel := map[ontology.Label]ontology.Node{}
	for _, n := range ev.Nodes {
		byLabel[n.Label] = n
	}

	vm, ok := byLabel[ontology.LabelVirtualMachine]
	if !ok || !vm.Bool(ontology.PropInternetExposed) {
		t.Errorf("EC2 should be an internet-exposed VirtualMachine: %+v", vm)
	}
	if vm.Name != "web-frontend" {
		t.Errorf("VM name = %q, want web-frontend (from Name tag)", vm.Name)
	}
	role, ok := byLabel[ontology.LabelIAMRole]
	if !ok || !role.Bool(ontology.PropCrownJewel) {
		t.Errorf("admin role should be a crown jewel: %+v", role)
	}
	bucket, ok := byLabel[ontology.LabelBucket]
	if !ok || !bucket.Bool(ontology.PropCrownJewel) {
		t.Errorf("sensitive bucket should be a crown jewel: %+v", bucket)
	}

	// Relationship edges: LB -ROUTES_TO-> VM -ASSUMES-> role -HAS_PERMISSION-> bucket.
	want := map[ontology.EdgeType]bool{
		ontology.EdgeRoutesTo:      false,
		ontology.EdgeAssumes:       false,
		ontology.EdgeHasPermission: false,
	}
	for _, e := range ev.Edges {
		if _, tracked := want[e.Type]; tracked {
			want[e.Type] = true
		}
	}
	for et, seen := range want {
		if !seen {
			t.Errorf("missing %s edge", et)
		}
	}
}
