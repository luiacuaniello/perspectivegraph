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

// Exposure is decided port by port and per address family: IPv6 sources are read from
// Ipv6Ranges, where AWS puts them; ICMP alone is no way in; lateral edges carry the ports
// they open; and a bundle that names no protocol keeps meaning "all traffic".
func TestExposureByPortAndFamily(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "security_groups": [
	    { "GroupId": "sg-v6", "IpPermissions": [
	        { "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "Ipv6Ranges": [ { "CidrIpv6": "::/0" } ] } ] },
	    { "GroupId": "sg-ping", "IpPermissions": [
	        { "IpProtocol": "icmp", "FromPort": 8, "ToPort": -1, "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] },
	    { "GroupId": "sg-legacy", "IpPermissions": [ { "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] },
	    { "GroupId": "sg-db", "IpPermissions": [
	        { "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [ { "GroupId": "sg-legacy" } ] },
	        { "IpProtocol": "icmp", "UserIdGroupPairs": [ { "GroupId": "sg-ping" } ] } ] }
	  ],
	  "instances": [
	    { "InstanceId": "i-v6",     "SubnetId": "subnet-v6", "SecurityGroups": [ { "GroupId": "sg-v6" } ] },
	    { "InstanceId": "i-v6-v4route", "SubnetId": "subnet-v4", "SecurityGroups": [ { "GroupId": "sg-v6" } ] },
	    { "InstanceId": "i-ping",   "SecurityGroups": [ { "GroupId": "sg-ping" } ] },
	    { "InstanceId": "i-legacy", "SecurityGroups": [ { "GroupId": "sg-legacy" } ] },
	    { "InstanceId": "i-db",     "SecurityGroups": [ { "GroupId": "sg-db" } ] }
	  ],
	  "subnets": [ { "SubnetId": "subnet-v6", "RouteTableId": "rt-v6" }, { "SubnetId": "subnet-v4", "RouteTableId": "rt-v4" } ],
	  "route_tables": [
	    { "RouteTableId": "rt-v6", "Routes": [ { "DestinationIpv6CidrBlock": "::/0", "GatewayId": "igw-1" } ] },
	    { "RouteTableId": "rt-v4", "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1" } ] }
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
	ports := func(name string) string { s, _ := node(name).Properties["exposed_ports"].(string); return s }

	if ports("i-v6") != "tcp/443" || !node("i-v6").Bool(ontology.PropInternetExposed) {
		t.Errorf("i-v6 opens 443 on ::/0 under an IPv6 route to an internet gateway; exposed on %q", ports("i-v6"))
	}
	if node("i-v6-v4route").Bool(ontology.PropInternetExposed) {
		t.Error("i-v6-v4route opens 443 on IPv6 only, and its subnet routes only IPv4 to the internet gateway")
	}
	if node("i-ping").Bool(ontology.PropInternetExposed) {
		t.Error("i-ping answers ICMP and nothing else; there is no service to attack")
	}
	if note, _ := node("i-ping").Properties["net_reachability"].(string); !strings.Contains(note, "only icmp") {
		t.Errorf("i-ping note %q, want it to say only ICMP reaches it", note)
	}
	if ports("i-legacy") != "tcp/all, udp/all, icmp, icmpv6" {
		t.Errorf("a rule with no protocol means all traffic, as it did; i-legacy exposed on %q", ports("i-legacy"))
	}
	if mgmt, _ := node("i-legacy").Properties["exposed_management_ports"].(string); !strings.Contains(mgmt, "tcp/22") {
		t.Errorf("all of TCP open to the internet includes SSH; management ports %q", mgmt)
	}

	lateral := map[string]string{}
	for _, e := range events[0].Edges {
		if e.Type == ontology.EdgeConnectsTo {
			p, _ := e.Properties["ports"].(string)
			lateral[byID[e.From].Name+"->"+byID[e.To].Name] = p
		}
	}
	if lateral["i-legacy->i-db"] != "tcp/5432" {
		t.Errorf("i-legacy reaches i-db on %q, want tcp/5432", lateral["i-legacy->i-db"])
	}
	if _, ok := lateral["i-ping->i-db"]; ok {
		t.Error("a group that admits only ICMP from another is a ping, not a lateral route")
	}
}

// An ECS service is a workload with security groups, subnets and maybe a public address:
// exposed by the same rules as an instance, holding its task role, and a source of lateral
// routes like any member of its groups.
func TestECSServicesAreWorkloads(t *testing.T) {
	const bundle = `{
	  "provider": "aws",
	  "security_groups": [
	    { "GroupId": "sg-web", "IpPermissions": [
	        { "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] },
	    { "GroupId": "sg-db", "IpPermissions": [
	        { "IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": [ { "GroupId": "sg-web" } ] } ] }
	  ],
	  "instances": [ { "InstanceId": "i-db", "SecurityGroups": [ { "GroupId": "sg-db" } ], "Tags": [ { "Key": "Name", "Value": "orders-db" } ] } ],
	  "ecs_services": [
	    { "serviceArn": "arn:aws:ecs:eu-west-1:123456789012:service/prod/api", "serviceName": "api",
	      "clusterArn": "arn:aws:ecs:eu-west-1:123456789012:cluster/prod", "taskRoleArn": "arn:aws:iam::123456789012:role/api-task",
	      "assignPublicIp": "ENABLED", "securityGroups": [ "sg-web" ], "subnets": [ "subnet-pub" ] },
	    { "serviceArn": "arn:aws:ecs:eu-west-1:123456789012:service/prod/worker", "serviceName": "worker",
	      "clusterArn": "arn:aws:ecs:eu-west-1:123456789012:cluster/prod",
	      "assignPublicIp": "DISABLED", "securityGroups": [ "sg-web" ], "subnets": [ "subnet-pub" ] }
	  ],
	  "subnets": [ { "SubnetId": "subnet-pub", "RouteTableId": "rt-pub" } ],
	  "route_tables": [ { "RouteTableId": "rt-pub", "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1" } ] } ]
	}`
	events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{Account: "123456789012"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]ontology.Node{}
	for _, n := range events[0].Nodes {
		byName[n.Name] = n
	}
	api, worker := byName["api"], byName["worker"]
	if !api.InternetExposed() || api.Properties["exposed_ports"] != "tcp/443" {
		t.Errorf("api has a public address in a public subnet with 443 open: exposed=%v on %v", api.InternetExposed(), api.Properties["exposed_ports"])
	}
	if worker.InternetExposed() {
		t.Error("worker assigns no public address: the open group reaches nothing")
	}
	if note, _ := worker.Properties["net_reachability"].(string); !strings.Contains(note, "no public IPv4") {
		t.Errorf("worker note %q, want it to say there is no public address", note)
	}
	var role, lateral bool
	for _, e := range events[0].Edges {
		role = role || (e.Type == ontology.EdgeAssumes && e.From == api.ID &&
			e.To == ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::123456789012:role/api-task"))
		lateral = lateral || (e.Type == ontology.EdgeConnectsTo && e.From == api.ID && e.To == byName["orders-db"].ID &&
			e.Properties["ports"] == "tcp/5432")
	}
	if !role {
		t.Error("the api service holds its task role")
	}
	if !lateral {
		t.Error("the api service is in sg-web, which the database admits on 5432")
	}
}

// The front door of most AWS estates: an internet-facing load balancer in public subnets,
// the workloads behind it in private ones. Those workloads are rightly not exposed
// themselves; the load balancer is, on the ports its listeners serve that its groups
// admit, and it routes to its targets - an instance, an ECS service through its target
// group, a Lambda function, another load balancer.
func TestLoadBalancersAreTheFrontDoor(t *testing.T) {
	const acct = "123456789012"
	const arn = "arn:aws:elasticloadbalancing:eu-west-1:" + acct + ":"
	const bundle = `{
	  "security_groups": [
	    { "GroupId": "sg-alb", "IpPermissions": [
	        { "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] },
	        { "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] },
	    { "GroupId": "sg-only-443", "IpPermissions": [
	        { "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] },
	    { "GroupId": "sg-app", "IpPermissions": [
	        { "IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "UserIdGroupPairs": [ { "GroupId": "sg-alb" } ] } ] }
	  ],
	  "instances": [ { "InstanceId": "i-app", "SubnetId": "subnet-priv", "PrivateIpAddress": "10.0.2.10",
	                   "SecurityGroups": [ { "GroupId": "sg-app" } ], "Tags": [ { "Key": "Name", "Value": "app" } ] },
	                 { "InstanceId": "i-legacy", "SubnetId": "subnet-priv", "PrivateIpAddress": "10.0.2.20",
	                   "SecurityGroups": [ { "GroupId": "sg-app" } ], "Tags": [ { "Key": "Name", "Value": "legacy" } ] } ],
	  "ecs_services": [
	    { "serviceArn": "arn:aws:ecs:eu-west-1:` + acct + `:service/prod/api", "serviceName": "api",
	      "clusterArn": "arn:aws:ecs:eu-west-1:` + acct + `:cluster/prod", "assignPublicIp": "DISABLED",
	      "securityGroups": [ "sg-app" ], "subnets": [ "subnet-priv" ], "targetGroups": [ "` + arn + `targetgroup/api/1" ] } ],
	  "load_balancers": [
	    { "LoadBalancerArn": "` + arn + `loadbalancer/app/web/1", "LoadBalancerName": "web", "Type": "application",
	      "Scheme": "internet-facing", "IpAddressType": "ipv4", "SecurityGroups": [ "sg-alb" ],
	      "AvailabilityZones": [ { "SubnetId": "subnet-pub-a" }, { "SubnetId": "subnet-pub-b" } ],
	      "Listeners": [ { "Protocol": "HTTP", "Port": 80 }, { "Protocol": "HTTPS", "Port": 443 } ],
	      "TargetGroups": [
	        { "TargetGroupArn": "` + arn + `targetgroup/app/1", "TargetType": "instance", "Protocol": "HTTP", "Port": 8080,
	          "Targets": [ { "Id": "i-app" } ] },
	        { "TargetGroupArn": "` + arn + `targetgroup/api/1", "TargetType": "ip", "Protocol": "HTTP", "Port": 8080, "Targets": [] },
	        { "TargetGroupArn": "` + arn + `targetgroup/legacy/1", "TargetType": "ip", "Protocol": "HTTP", "Port": 8080,
	          "Targets": [ { "Id": "10.0.2.20", "Port": 9000 } ] },
	        { "TargetGroupArn": "` + arn + `targetgroup/fn/1", "TargetType": "lambda",
	          "Targets": [ { "Id": "arn:aws:lambda:eu-west-1:` + acct + `:function:thumbs:live" } ] } ] },
	    { "LoadBalancerArn": "` + arn + `loadbalancer/app/admin/2", "LoadBalancerName": "admin", "Type": "application",
	      "Scheme": "internal", "SecurityGroups": [ "sg-alb" ], "AvailabilityZones": [ { "SubnetId": "subnet-priv" } ],
	      "Listeners": [ { "Protocol": "HTTP", "Port": 80 } ] },
	    { "LoadBalancerArn": "` + arn + `loadbalancer/app/back-office/6", "LoadBalancerName": "back-office", "Type": "application",
	      "Scheme": "internal", "SecurityGroups": [ "sg-alb" ], "AvailabilityZones": [ { "SubnetId": "subnet-pub-a" } ],
	      "Listeners": [ { "Protocol": "HTTP", "Port": 80 } ] },
	    { "LoadBalancerArn": "` + arn + `loadbalancer/app/tls-only/3", "LoadBalancerName": "tls-only", "Type": "application",
	      "Scheme": "internet-facing", "SecurityGroups": [ "sg-only-443" ], "AvailabilityZones": [ { "SubnetId": "subnet-pub-a" } ],
	      "Listeners": [ { "Protocol": "HTTP", "Port": 80 } ] },
	    { "LoadBalancerArn": "` + arn + `loadbalancer/net/edge/4", "LoadBalancerName": "edge", "Type": "network",
	      "Scheme": "internet-facing", "AvailabilityZones": [ { "SubnetId": "subnet-pub-a" } ],
	      "Listeners": [ { "Protocol": "TCP", "Port": 22 }, { "Protocol": "TCP", "Port": 443 } ],
	      "TargetGroups": [ { "TargetGroupArn": "` + arn + `targetgroup/to-alb/4", "TargetType": "alb", "Protocol": "TCP", "Port": 443,
	          "Targets": [ { "Id": "` + arn + `loadbalancer/app/web/1" } ] } ] },
	    { "LoadBalancerArn": "` + arn + `loadbalancer/net/stranded/5", "LoadBalancerName": "stranded", "Type": "network",
	      "Scheme": "internet-facing", "AvailabilityZones": [ { "SubnetId": "subnet-priv" } ],
	      "Listeners": [ { "Protocol": "TCP", "Port": 443 } ] }
	  ],
	  "subnets": [ { "SubnetId": "subnet-pub-a", "RouteTableId": "rt-pub" }, { "SubnetId": "subnet-pub-b", "RouteTableId": "rt-pub" },
	               { "SubnetId": "subnet-priv", "RouteTableId": "rt-priv" } ],
	  "route_tables": [ { "RouteTableId": "rt-pub", "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1" } ] },
	                    { "RouteTableId": "rt-priv", "Routes": [ { "DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1" } ] } ]
	}`
	events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{Account: acct})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]ontology.Node{}
	for _, n := range events[0].Nodes {
		byName[n.Name] = n
	}
	for name, want := range map[string]string{"web": "tcp/80, tcp/443", "edge": "tcp/22, tcp/443", "admin": "", "back-office": "", "tls-only": "", "stranded": ""} {
		n, ok := byName[name]
		if !ok {
			t.Fatalf("load balancer %s not drawn", name)
		}
		if n.Label != ontology.LabelLoadBalancer || n.InternetExposed() != (want != "") || n.Properties["exposed_ports"] != want {
			t.Errorf("%s: exposed=%v on %q, want %q (%v)", name, n.InternetExposed(), n.Properties["exposed_ports"], want, n.Properties["net_reachability"])
		}
		// Written either way, so a load balancer made internal, or closed, is retracted.
		if v, ok := n.Properties[ontology.PropNetworkExposed]; !ok || v != (want != "") {
			t.Errorf("%s: network_exposed = %v (present=%v), want %v", name, v, ok, want != "")
		}
	}
	if byName["edge"].Properties["exposed_management_ports"] != "tcp/22" {
		t.Errorf("a network load balancer with no groups admits what it listens on, SSH included: %v", byName["edge"].Properties)
	}
	if byName["app"].InternetExposed() || byName["api"].InternetExposed() {
		t.Error("the workloads behind the load balancer sit in a private subnet: not exposed themselves")
	}
	// Keyed as the custodian collector keys a load balancer, so the two feeds meet.
	if want := ingestion.RegionalID(ontology.LabelLoadBalancer, acct, "eu-west-1", "web"); byName["web"].ID != want {
		t.Errorf("web id %s, want the custodian collector's %s", byName["web"].ID, want)
	}
	routes := map[string]string{}
	for _, e := range events[0].Edges {
		if e.Type == ontology.EdgeRoutesTo {
			ports, _ := e.Properties["ports"].(string)
			routes[e.From+">"+e.To] = ports
		}
	}
	web, edge := byName["web"].ID, byName["edge"].ID
	for to, ports := range map[string]string{
		byName["app"].ID:    "tcp/8080",
		byName["api"].ID:    "tcp/8080",
		byName["legacy"].ID: "tcp/9000",
		ontology.NewID(ontology.LabelFunction, "arn:aws:lambda:eu-west-1:"+acct+":function:thumbs"): "",
	} {
		got, ok := routes[web+">"+to]
		if !ok || got != ports {
			t.Errorf("web should route to %s on %q, got %q (present=%v)", to, ports, got, ok)
		}
	}
	if _, ok := routes[edge+">"+web]; !ok {
		t.Error("the network load balancer forwards to the application load balancer it targets")
	}
	if len(routes) != 5 {
		t.Errorf("routes = %v, want the five above", routes)
	}
}
