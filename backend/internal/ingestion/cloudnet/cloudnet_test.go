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

// An instance's IAM instance profile is the hop that turns "a box on the network" into
// "an identity": it is what an attacker with a foothold reads out of IMDS. EC2 reports
// only the profile ARN, so the collector resolves it to the role (keyed by ARN, matching
// the iam collector) and prices the hop on the instance's real IMDS posture.
func TestInstanceProfileAssumesRoleGatedByImds(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "security_groups": [ { "GroupId": "sg-a", "IpPermissions": [] } ],
	  "instances": [
	    { "InstanceId": "i-imdsv1",    "SecurityGroups": [ { "GroupId": "sg-a" } ],
	      "IamInstanceProfile": { "Arn": "arn:aws:iam::1:instance-profile/p-a" },
	      "MetadataOptions": { "HttpTokens": "optional" } },
	    { "InstanceId": "i-imdsv2",    "SecurityGroups": [ { "GroupId": "sg-a" } ],
	      "IamInstanceProfile": { "Arn": "arn:aws:iam::1:instance-profile/p-a" },
	      "MetadataOptions": { "HttpTokens": "required" } },
	    { "InstanceId": "i-noprofile", "SecurityGroups": [ { "GroupId": "sg-a" } ] },
	    { "InstanceId": "i-unknown",   "SecurityGroups": [ { "GroupId": "sg-a" } ],
	      "IamInstanceProfile": { "Arn": "arn:aws:iam::1:instance-profile/p-missing" } }
	  ],
	  "instance_profiles": [
	    { "Arn": "arn:aws:iam::1:instance-profile/p-a",
	      "Roles": [ { "Arn": "arn:aws:iam::1:role/app-role", "RoleName": "app-role" } ] }
	  ]
	}`
	events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	roleID := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::1:role/app-role")
	assumes := map[string]float64{}
	for _, e := range events[0].Edges {
		if e.Type == ontology.EdgeAssumes && e.To == roleID {
			assumes[e.From] = e.ExploitProbability
		}
	}
	vm := func(name string) string { return ontology.NewID(ontology.LabelVirtualMachine, name) }

	if got := assumes[vm("i-imdsv1")]; got != 0.9 {
		t.Errorf("IMDSv1 (HttpTokens=optional) ASSUMES p = %v, want 0.9 - a blind SSRF reads the credentials", got)
	}
	if got := assumes[vm("i-imdsv2")]; got != 0.6 {
		t.Errorf("IMDSv2 (HttpTokens=required) ASSUMES p = %v, want 0.6 - the attacker must mint a token first", got)
	}
	if _, ok := assumes[vm("i-noprofile")]; ok {
		t.Error("an instance with no profile must not assume a role")
	}
	if _, ok := assumes[vm("i-unknown")]; ok {
		t.Error("an unresolvable profile ARN must not invent a role edge")
	}
	// The role node must exist so the edge is not dangling before the iam feed arrives.
	var haveRole bool
	for _, n := range events[0].Nodes {
		if n.ID == roleID && n.Name == "app-role" {
			haveRole = true
		}
	}
	if !haveRole {
		t.Error("missing the IAM_Role node the ASSUMES edge points at")
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

// The reason the account dimension exists. Instance ids are unique within an account,
// not across them, so ingesting two accounts that each have an i-shared has to produce
// two machines. Keyed on the id alone they merged into one node - and a merged node
// inherits both accounts' edges, which manufactures paths that cross an account boundary
// nothing actually crosses.
func TestSameInstanceIdInTwoAccountsStaysTwoMachines(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "security_groups": [ { "GroupId": "sg-open", "IpPermissions": [ { "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] } ],
	  "instances": [ { "InstanceId": "i-shared", "SecurityGroups": [ { "GroupId": "sg-open" } ] } ]
	}`

	ids := map[string]string{}
	for _, account := range []string{"111111111111", "222222222222"} {
		evs, err := New().Parse(strings.NewReader(bundle), ingestion.Options{Account: account})
		if err != nil {
			t.Fatalf("parse (%s): %v", account, err)
		}
		for _, ev := range evs {
			for _, n := range ev.Nodes {
				if n.Label != ontology.LabelVirtualMachine {
					continue
				}
				ids[account] = n.ID
				if got := n.Properties[ontology.PropAccount]; got != account {
					t.Errorf("account %s: node carries account %v, want %s", account, got, account)
				}
			}
		}
	}
	if len(ids) != 2 {
		t.Fatalf("expected a machine from each account, got %v", ids)
	}
	if ids["111111111111"] == ids["222222222222"] {
		t.Error("the same instance id in two accounts produced ONE node - the accounts merged")
	}
}

// An estate that sends no account must keep the ids it already has. Otherwise this
// change would silently orphan every existing node in every deployment on upgrade.
func TestWithoutAnAccountTheIdsAreUnchanged(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "security_groups": [ { "GroupId": "sg-open", "IpPermissions": [ { "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] } ],
	  "instances": [ { "InstanceId": "i-legacy", "SecurityGroups": [ { "GroupId": "sg-open" } ] } ]
	}`
	evs, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := ontology.NewID(ontology.LabelVirtualMachine, "i-legacy")
	var found bool
	for _, ev := range evs {
		for _, n := range ev.Nodes {
			if n.Label != ontology.LabelVirtualMachine {
				continue
			}
			found = true
			if n.ID != want {
				t.Errorf("id changed for a single-account estate: got %s, want %s", n.ID, want)
			}
			if _, ok := n.Properties[ontology.PropAccount]; ok {
				t.Error("an account property was invented for a report that carried none")
			}
		}
	}
	if !found {
		t.Fatal("no machine parsed")
	}
}
