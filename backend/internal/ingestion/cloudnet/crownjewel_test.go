package cloudnet

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A crown jewel that exists because someone wrote a tag must arrive saying so.
//
// `ec2:CreateTags` is granted freely because tagging looks harmless, so the tag is the
// one crown-jewel signal an attacker can forge - and the analyzer already ranks a
// tag-derived target below an authoritatively classified one. That ranking reads
// crown_jewel_basis. If ingestion sets the flag without the provenance, the distinction
// the design depends on never reaches the code that would apply it.
func TestTagDerivedCrownJewelCarriesItsProvenance(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "instances": [
	    { "InstanceId": "i-jewel", "Tags": [ { "Key": "classification", "Value": "pii" } ] }
	  ]
	}`
	events, err := (&Collector{}).Parse(strings.NewReader(bundle), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, ev := range events {
		for _, n := range ev.Nodes {
			if !n.Bool(ontology.PropCrownJewel) {
				continue
			}
			found = true
			basis, _ := n.Properties[ontology.PropCrownJewelBasis].(string)
			if basis != "tagged" {
				t.Errorf("a jewel from a tag must record basis %q, got %q - the analyzer ranks on this",
					"tagged", basis)
			}
		}
	}
	if !found {
		t.Fatal("the tagged instance was not marked a crown jewel at all")
	}
}
