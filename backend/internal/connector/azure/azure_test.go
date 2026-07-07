package azure

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const fixture = "../../../testdata/azure-network-sample.json"

// The whole pull, on fixtures: normalized Azure state -> mapped to cloudnet ->
// parsed by the existing collector -> the same ontology events the file-upload path
// produces. The web VM behind the Internet-open NSG must surface as an
// internet-exposed node, and the PII db VM tagged crown-jewel as a crown jewel.
func TestAzureConnectorFixturesPull(t *testing.T) {
	c, err := NewFromConfig(context.Background(), Config{Mode: "fixtures", FixturesDir: "../../../testdata"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Source() != "azure" || c.Mode() != "fixtures" {
		t.Fatalf("source=%q mode=%q, want azure/fixtures", c.Source(), c.Mode())
	}
	evs, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("no events from the Azure fixtures pull")
	}
	names := map[string]bool{}
	exposed, jewel := false, false
	for _, ev := range evs {
		for _, n := range ev.Nodes {
			names[n.Name] = true
			if n.Bool(ontology.PropInternetExposed) {
				exposed = true
			}
			if n.Bool(ontology.PropCrownJewel) {
				jewel = true
			}
		}
	}
	if !names["web-vm"] {
		t.Error("expected a web-vm node from the pull")
	}
	if !exposed {
		t.Error("the web VM behind the Internet-open NSG should be internet-exposed")
	}
	if !jewel {
		t.Error("the PII db VM tagged crown-jewel should be a crown jewel")
	}
}

// The mapper's core job: Azure's "Internet" service tag becomes 0.0.0.0/0 (so
// cloudnet flags exposure) while a specific CIDR is preserved as-is.
func TestMapNetworkToCloudnet(t *testing.T) {
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	out, err := mapNetworkToCloudnet(raw)
	if err != nil {
		t.Fatal(err)
	}
	var b cloudnetBundle
	if err := json.Unmarshal(out, &b); err != nil {
		t.Fatal(err)
	}
	if b.Provider != "azure" {
		t.Errorf("provider = %q, want azure", b.Provider)
	}
	if !sgHasCIDR(b, "web-nsg", "0.0.0.0/0") {
		t.Error("web-nsg: the Internet service tag must map to 0.0.0.0/0")
	}
	if sgHasCIDR(b, "db-nsg", "0.0.0.0/0") {
		t.Error("db-nsg (source 10.0.1.0/24) must NOT be opened to the internet")
	}
	if !sgHasCIDR(b, "db-nsg", "10.0.1.0/24") {
		t.Error("db-nsg should preserve its specific source CIDR")
	}
}

func sgHasCIDR(b cloudnetBundle, sg, cidr string) bool {
	for _, g := range b.SecurityGroups {
		if g.GroupID != sg {
			continue
		}
		for _, p := range g.IpPermissions {
			for _, r := range p.IpRanges {
				if r.CidrIp == cidr {
					return true
				}
			}
		}
	}
	return false
}
