package cloudnet

import (
	"os"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestDiscoversReachability(t *testing.T) {
	f, err := os.Open("../../../testdata/cloudnet-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	events, err := New().Parse(f, ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ev := events[0]

	byID := map[string]ontology.Node{}
	for _, n := range ev.Nodes {
		byID[n.ID] = n
	}
	web := ontology.NewID(ontology.LabelVirtualMachine, "i-web")
	db := ontology.NewID(ontology.LabelVirtualMachine, "i-db")

	if !byID[web].Bool(ontology.PropInternetExposed) {
		t.Error("i-web (0.0.0.0/0 ingress) should be internet-exposed")
	}
	if byID[web].Bool(ontology.PropCrownJewel) {
		t.Error("i-web should not be a crown jewel")
	}
	if !byID[db].Bool(ontology.PropCrownJewel) {
		t.Error("i-db (classification=pii) should be a crown jewel")
	}

	connects := false
	for _, e := range ev.Edges {
		if e.Type == ontology.EdgeConnectsTo && e.From == web && e.To == db {
			connects = true
		}
	}
	if !connects {
		t.Error("missing discovered i-web --CONNECTS_TO--> i-db (sg-db admits sg-web)")
	}

	// VPC peering edge present.
	peering := false
	for _, e := range ev.Edges {
		if e.Type == ontology.EdgeConnectsTo &&
			e.From == ontology.NewID(ontology.LabelVPC, "vpc-app") &&
			e.To == ontology.NewID(ontology.LabelVPC, "vpc-data") {
			peering = true
		}
	}
	if !peering {
		t.Error("missing VPC peering CONNECTS_TO edge")
	}
}
