package cloudnet

import (
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Reachability precision: an open SG is necessary but not sufficient. With route
// table + NACL data, an instance is internet-exposed ONLY if its subnet routes to an
// IGW and its NACL admits the internet - so a private-subnet or NACL-denied instance
// is correctly NOT a seed (the classic false positive), while an instance carrying no
// subnet info falls back to the SG-only heuristic.
func TestRouteAndNaclGateInternetExposure(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "security_groups": [ { "GroupId": "sg-open", "IpPermissions": [ { "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] } ],
	  "instances": [
	    { "InstanceId": "i-public",   "SubnetId": "subnet-pub",  "SecurityGroups": [ { "GroupId": "sg-open" } ] },
	    { "InstanceId": "i-private",  "SubnetId": "subnet-priv", "SecurityGroups": [ { "GroupId": "sg-open" } ] },
	    { "InstanceId": "i-nacldeny", "SubnetId": "subnet-deny", "SecurityGroups": [ { "GroupId": "sg-open" } ] },
	    { "InstanceId": "i-nosubnet", "SecurityGroups": [ { "GroupId": "sg-open" } ] }
	  ],
	  "subnets": [
	    { "SubnetId": "subnet-pub",  "RouteTableId": "rt-public",  "NetworkAclId": "acl-allow" },
	    { "SubnetId": "subnet-priv", "RouteTableId": "rt-private", "NetworkAclId": "acl-allow" },
	    { "SubnetId": "subnet-deny", "RouteTableId": "rt-public",  "NetworkAclId": "acl-deny" }
	  ],
	  "route_tables": [
	    { "RouteTableId": "rt-public",  "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123" } ] },
	    { "RouteTableId": "rt-private", "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "nat-abc" } ] }
	  ],
	  "network_acls": [
	    { "NetworkAclId": "acl-allow", "Entries": [ { "RuleNumber": 100, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow" } ] },
	    { "NetworkAclId": "acl-deny",  "Entries": [ { "RuleNumber": 100, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "deny" } ] }
	  ]
	}`
	events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byID := map[string]ontology.Node{}
	for _, n := range events[0].Nodes {
		byID[n.ID] = n
	}
	exposed := func(name string) bool {
		return byID[ontology.NewID(ontology.LabelVirtualMachine, name)].Bool(ontology.PropInternetExposed)
	}
	if !exposed("i-public") {
		t.Error("i-public (IGW route + allowing NACL) should be internet-exposed")
	}
	if exposed("i-private") {
		t.Error("i-private (no IGW route, only a NAT) must NOT be internet-exposed - the false positive this fixes")
	}
	if exposed("i-nacldeny") {
		t.Error("i-nacldeny (routed but the NACL denies internet ingress) must NOT be internet-exposed")
	}
	if !exposed("i-nosubnet") {
		t.Error("i-nosubnet (no subnet data) should fall back to the SG-only heuristic and be exposed")
	}
}

// Real route tables point 0.0.0.0/0 (or ::/0) at many target kinds, only one of which
// - the internet gateway - is actually inbound-reachable. A NAT / transit-gateway /
// egress-only-IGW default route is private egress, and the audit note should say which.
// IPv6-only public subnets (::/0 → igw) must still be exposed.
func TestRouteTargetClassificationAndIPv6(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "security_groups": [ { "GroupId": "sg-open", "IpPermissions": [ { "IpRanges": [ { "CidrIp": "0.0.0.0/0" }, { "CidrIp": "::/0" } ] } ] } ],
	  "instances": [
	    { "InstanceId": "i-nat",      "SubnetId": "subnet-nat",   "SecurityGroups": [ { "GroupId": "sg-open" } ] },
	    { "InstanceId": "i-tgw",      "SubnetId": "subnet-tgw",   "SecurityGroups": [ { "GroupId": "sg-open" } ] },
	    { "InstanceId": "i-v6pub",    "SubnetId": "subnet-v6",    "SecurityGroups": [ { "GroupId": "sg-open" } ] },
	    { "InstanceId": "i-v6egress", "SubnetId": "subnet-eigw",  "SecurityGroups": [ { "GroupId": "sg-open" } ] }
	  ],
	  "subnets": [
	    { "SubnetId": "subnet-nat",  "RouteTableId": "rt-nat"  },
	    { "SubnetId": "subnet-tgw",  "RouteTableId": "rt-tgw"  },
	    { "SubnetId": "subnet-v6",   "RouteTableId": "rt-v6"   },
	    { "SubnetId": "subnet-eigw", "RouteTableId": "rt-eigw" }
	  ],
	  "route_tables": [
	    { "RouteTableId": "rt-nat",  "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1" } ] },
	    { "RouteTableId": "rt-tgw",  "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "TransitGatewayId": "tgw-1" } ] },
	    { "RouteTableId": "rt-v6",   "Routes": [ { "DestinationCidrBlock": "::/0", "GatewayId": "igw-1" } ] },
	    { "RouteTableId": "rt-eigw", "Routes": [ { "DestinationCidrBlock": "::/0", "EgressOnlyInternetGatewayId": "eigw-1" } ] }
	  ]
	}`
	events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byID := map[string]ontology.Node{}
	for _, n := range events[0].Nodes {
		byID[n.ID] = n
	}
	node := func(name string) ontology.Node { return byID[ontology.NewID(ontology.LabelVirtualMachine, name)] }
	exposed := func(name string) bool { return node(name).Bool(ontology.PropInternetExposed) }
	note := func(name string) string {
		s, _ := node(name).Properties["net_reachability"].(string)
		return s
	}

	if !exposed("i-v6pub") {
		t.Error("i-v6pub (::/0 → internet gateway) should be internet-exposed even though it is IPv6-only")
	}
	for _, tc := range []struct {
		name, want string
	}{
		{"i-nat", "NAT gateway"},
		{"i-tgw", "transit gateway"},
		{"i-v6egress", "egress-only internet gateway"},
	} {
		if exposed(tc.name) {
			t.Errorf("%s routes to the internet only via %s, not an IGW - must NOT be exposed", tc.name, tc.want)
		}
		if !strings.Contains(note(tc.name), tc.want) {
			t.Errorf("%s net_reachability note = %q, want it to mention %q", tc.name, note(tc.name), tc.want)
		}
	}
}

// NACLs are stateless and evaluated in ascending rule-number order, first match wins.
// The bundle may list entries out of order, and rules on narrower (non-internet) CIDRs
// must be skipped when deciding whether the internet is admitted.
func TestNaclRuleOrdering(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "security_groups": [ { "GroupId": "sg-open", "IpPermissions": [ { "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] } ],
	  "instances": [
	    { "InstanceId": "i-denyfirst",  "SubnetId": "subnet-df", "SecurityGroups": [ { "GroupId": "sg-open" } ] },
	    { "InstanceId": "i-allowfirst", "SubnetId": "subnet-af", "SecurityGroups": [ { "GroupId": "sg-open" } ] },
	    { "InstanceId": "i-narrowdeny", "SubnetId": "subnet-nd", "SecurityGroups": [ { "GroupId": "sg-open" } ] }
	  ],
	  "subnets": [
	    { "SubnetId": "subnet-df", "RouteTableId": "rt-pub", "NetworkAclId": "acl-denyfirst"  },
	    { "SubnetId": "subnet-af", "RouteTableId": "rt-pub", "NetworkAclId": "acl-allowfirst" },
	    { "SubnetId": "subnet-nd", "RouteTableId": "rt-pub", "NetworkAclId": "acl-narrow"     }
	  ],
	  "route_tables": [
	    { "RouteTableId": "rt-pub", "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1" } ] }
	  ],
	  "network_acls": [
	    { "NetworkAclId": "acl-denyfirst",  "Entries": [
	        { "RuleNumber": 200, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow" },
	        { "RuleNumber": 100, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "deny" } ] },
	    { "NetworkAclId": "acl-allowfirst", "Entries": [
	        { "RuleNumber": 200, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "deny" },
	        { "RuleNumber": 100, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow" } ] },
	    { "NetworkAclId": "acl-narrow",     "Entries": [
	        { "RuleNumber": 90,  "Egress": false, "CidrBlock": "10.0.0.0/8", "RuleAction": "deny" },
	        { "RuleNumber": 100, "Egress": false, "CidrBlock": "0.0.0.0/0",  "RuleAction": "allow" } ] }
	  ]
	}`
	events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byID := map[string]ontology.Node{}
	for _, n := range events[0].Nodes {
		byID[n.ID] = n
	}
	exposed := func(name string) bool {
		return byID[ontology.NewID(ontology.LabelVirtualMachine, name)].Bool(ontology.PropInternetExposed)
	}
	if exposed("i-denyfirst") {
		t.Error("acl-denyfirst: the lower rule number (100) denies the internet - first match wins, must NOT be exposed")
	}
	if !exposed("i-allowfirst") {
		t.Error("acl-allowfirst: the lower rule number (100) allows the internet - should be exposed")
	}
	if !exposed("i-narrowdeny") {
		t.Error("acl-narrow: the rule-90 deny is on 10.0.0.0/8 (not the internet) and must be skipped - rule 100 allows, should be exposed")
	}
}

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
