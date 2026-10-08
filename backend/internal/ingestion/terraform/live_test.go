package terraform_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/apigateway"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/terraform"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A security group is shared by whatever uses it, and a plan describes only what its
// configuration manages. These cases change a group the configuration does not hold, or
// one that instances outside it use: the plan alone says it cannot tell, and laid over the
// account's network, as a live read gives it, it tells.

// sharedWeb is the account as the AWS connector reads it: web-1, with a public address and
// the role web through its profile, in the group sg-0live, which a configuration elsewhere
// manages. Its subnet routes to an internet gateway when igw is set, and its network ACL
// lets in only the ports given, or everything when none are.
func sharedWeb(t *testing.T, ingress []any, igw bool, aclPorts ...int) []byte {
	t.Helper()
	return marshal(t, sharedWebMap(ingress, igw, aclPorts...))
}

func sharedWebMap(ingress []any, igw bool, aclPorts ...int) map[string]any {
	routes := []any{map[string]any{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}}
	if igw {
		routes = append(routes, map[string]any{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0live"})
	}
	entries := []any{map[string]any{"RuleNumber": 100, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow", "Protocol": "-1"}}
	if len(aclPorts) > 0 {
		entries = nil
		for i, port := range aclPorts {
			entries = append(entries, map[string]any{"RuleNumber": 100 + i, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow",
				"Protocol": "6", "PortRange": map[string]any{"From": port, "To": port}})
		}
	}
	return map[string]any{
		"provider":        "aws",
		"security_groups": []any{map[string]any{"GroupId": "sg-0live", "GroupName": "shared-web", "IpPermissions": ingress}},
		"instances": []any{map[string]any{"InstanceId": "i-0live", "SubnetId": "subnet-0live",
			"SecurityGroups":     []any{map[string]any{"GroupId": "sg-0live"}},
			"Tags":               []any{map[string]any{"Key": "Name", "Value": "web-1"}},
			"IamInstanceProfile": map[string]any{"Arn": "arn:aws:iam::" + account + ":instance-profile/web"},
			// Its public address is on an interface, as an Elastic IP on a second one is:
			// what the plan does not model passes through as the account wrote it.
			"PrivateIpAddress":  "10.0.1.10",
			"NetworkInterfaces": []any{map[string]any{"Association": map[string]any{"PublicIp": "203.0.113.10"}}}}},
		"vpc_peerings": []any{},
		"subnets":      []any{map[string]any{"SubnetId": "subnet-0live", "RouteTableId": "rtb-0live", "NetworkAclId": "acl-0live"}},
		"route_tables": []any{map[string]any{"RouteTableId": "rtb-0live", "Routes": routes}},
		"network_acls": []any{map[string]any{"NetworkAclId": "acl-0live", "Entries": entries}},
		"instance_profiles": []any{map[string]any{"Arn": "arn:aws:iam::" + account + ":instance-profile/web",
			"Roles": []any{map[string]any{"Arn": "arn:aws:iam::" + account + ":role/web", "RoleName": "web"}}}},
	}
}

func marshal(t *testing.T, x any) []byte {
	t.Helper()
	b, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func perm(port int, cidr string) map[string]any {
	return map[string]any{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": []any{map[string]any{"CidrIp": cidr}}}
}

// verdictLive runs the plan as local mode does with -aws-region: the estate is what the
// live read returned, and the plan's network is laid over the network feed it fetched.
func verdictLive(t *testing.T, plan string, live []byte) impact.Result {
	t.Helper()
	return verdictFeeds(t, plan, map[string][]byte{"cloudnet": live}, true)
}

// verdictFeeds runs the plan against an estate read from the given feeds, laid over them
// when overlay is set (local mode with -aws-region), or not (the server, whose graph holds
// what the feeds said and not the feeds themselves).
func verdictFeeds(t *testing.T, plan string, feeds map[string][]byte, overlay bool) impact.Result {
	t.Helper()
	var estate graph.Snapshot
	for feed, col := range map[string]ingestion.Collector{"cloudnet": cloudnet.New(), "apigateway": apigateway.New()} {
		if feeds[feed] == nil {
			continue
		}
		evs, err := col.Parse(bytes.NewReader(feeds[feed]), ingestion.Options{Account: account})
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range evs {
			estate.Nodes = append(estate.Nodes, ev.Nodes...)
			estate.Edges = append(estate.Edges, ev.Edges...)
		}
	}
	opts := ingestion.Options{RepoSlug: "acme/infra", CommitSHA: "c0ffee", Account: account, EstateKnown: true}
	if overlay {
		opts.LiveFeeds = feeds
	}
	ch, err := terraform.New().ParseChange(strings.NewReader(plan), opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := impact.Evaluate(context.Background(), impact.Input{Base: estate, BaseChange: ch.Before, Change: ch.After,
		Unknown: ch.Unknown, Outside: ch.Outside, Slug: "acme/infra", SHA: "c0ffee"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The role web is account administrator, and this configuration manages it.
func adminRole() []res {
	return []res{
		{addr: "aws_iam_role.web", values: map[string]any{"name": "web", "path": "/", "arn": "arn:aws:iam::" + account + ":role/web",
			"assume_role_policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}},
		{addr: "aws_iam_role_policy_attachment.admin", values: map[string]any{"id": "web-x", "role": "web",
			"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
	}
}

func with(prior []res, more ...res) []res {
	return append(append([]res(nil), prior...), more...)
}

// A rule this configuration adds to a group another one manages. The instance it opens is
// not in the plan, so the plan alone finds no route, and must not call that clean.
func TestARuleOnASharedGroupReachesTheInstancesThatUseIt(t *testing.T) {
	rule := res{addr: "aws_security_group_rule.ssh", actions: []string{"create"}, values: map[string]any{"type": "ingress",
		"security_group_id": "sg-0live", "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}},
		unknown: map[string]any{"id": true}}
	plan := planOf(t, adminRole(), with(adminRole(), rule))
	route := "introduced: web-1 -> web -> account-admin (effective)"

	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "outside the plan - security group sg-0live is opened to the internet on tcp/22") {
		t.Errorf("plan alone: routes %v, incomplete %q - want none found, and the group named as outside the plan", routes(r), r.Incomplete)
	}

	closed := []any{perm(443, "10.0.0.0/8")}
	r = verdictLive(t, plan, sharedWeb(t, closed, true))
	if !has(routes(r), route) || r.Incomplete != "" {
		t.Errorf("against the account: routes %v, incomplete %q - web-1 uses the group the rule opens", routes(r), r.Incomplete)
	}
	// What the account says about web-1's own network still decides, and the plan never
	// saw any of it: a subnet with no route to an internet gateway, a network ACL that lets
	// in only HTTPS.
	if r := verdictLive(t, plan, sharedWeb(t, closed, false)); len(r.Blocking) != 0 || r.Incomplete != "" {
		t.Errorf("a private subnet: routes %v, incomplete %q, want a clean answer", routes(r), r.Incomplete)
	}
	if r := verdictLive(t, plan, sharedWeb(t, closed, true, 443)); len(r.Blocking) != 0 || r.Incomplete != "" {
		t.Errorf("a network ACL that admits only 443: routes %v, incomplete %q, want a clean answer", routes(r), r.Incomplete)
	}
	// The rule alone, with nothing else in the configuration: web-1 is what the change
	// changes, so it is what the verdict is about.
	if r := verdictLive(t, planOf(t, nil, []res{rule}), sharedWeb(t, closed, true)); !r.Analysed || !r.Reachable {
		t.Errorf("the rule alone: analysed=%v reachable=%v, want web-1 judged as the change's", r.Analysed, r.Reachable)
	}
	// A rule that was there before the plan opens nothing new.
	if r := verdictLive(t, planOf(t, with(adminRole(), rule), with(adminRole(), rule)), sharedWeb(t, []any{perm(22, "0.0.0.0/0")}, true)); len(r.Blocking) != 0 {
		t.Errorf("an unchanged rule: %v", routes(r))
	}
}

// An instance this configuration launches into a group another one manages: the group's
// rules are not in the plan, so what reaches the instance is not either.
func TestAnInstanceJoiningASharedGroupMeetsItsRules(t *testing.T) {
	worker := res{addr: "aws_instance.worker", actions: []string{"create"}, values: map[string]any{"subnet_id": "subnet-0live",
		"vpc_security_group_ids": []any{"sg-0live"}, "iam_instance_profile": "web", "tags": map[string]any{"Name": "worker-1"}},
		unknown: map[string]any{"id": true, "public_ip": true, "private_ip": true, "associate_public_ip_address": true}}
	plan := planOf(t, adminRole(), with(adminRole(), worker))

	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "aws_instance.worker: its security group sg-0live has rules the configuration does not hold") {
		t.Errorf("plan alone: routes %v, incomplete %q", routes(r), r.Incomplete)
	}

	r = verdictLive(t, plan, sharedWeb(t, []any{perm(22, "0.0.0.0/0")}, true))
	if got := routes(r); !has(got, "introduced: worker-1 -> web -> account-admin (effective)") || r.Incomplete != "" {
		t.Errorf("against the account: routes %v, incomplete %q - the group admits SSH from anywhere", got, r.Incomplete)
	}
	// web-1's route through the same group was there before: it is not the plan's doing.
	if has(routes(r), "introduced: web-1 -> web -> account-admin (effective)") {
		t.Errorf("routes %v: web-1's route predates the plan", routes(r))
	}
	// The group's rules in the account stand beside the ones the plan adds to it.
	inside := res{addr: "aws_security_group_rule.metrics", actions: []string{"create"}, values: map[string]any{"type": "ingress",
		"security_group_id": "sg-0live", "from_port": 9100, "to_port": 9100, "protocol": "tcp", "cidr_blocks": []any{"10.0.0.0/8"}},
		unknown: map[string]any{"id": true}}
	r = verdictLive(t, planOf(t, adminRole(), with(adminRole(), worker, inside)), sharedWeb(t, []any{perm(22, "0.0.0.0/0")}, true))
	if !has(routes(r), "introduced: worker-1 -> web -> account-admin (effective)") {
		t.Errorf("with a rule of the plan's on the group: %v - the account's own rule still admits SSH", routes(r))
	}
	// Once launched, a plan that leaves it as it is has nothing outside it to report.
	running := worker
	running.actions, running.unknown = nil, nil
	running.values = map[string]any{"id": "i-0worker", "subnet_id": "subnet-0live", "vpc_security_group_ids": []any{"sg-0live"},
		"iam_instance_profile": "web", "private_ip": "10.0.1.11", "public_ip": "", "tags": map[string]any{"Name": "worker-1"}}
	if r := verdict(t, planOf(t, with(adminRole(), running), with(adminRole(), running))); r.Incomplete != "" {
		t.Errorf("an unchanged instance: incomplete %q", r.Incomplete)
	}
}

// A group this configuration creates, admitting one another manages: whatever is in that
// one reaches the new database.
func TestANewGroupLettingInASharedOne(t *testing.T) {
	sg := res{addr: "aws_security_group.db", actions: []string{"create"}, values: map[string]any{"name": "db", "ingress": []any{
		map[string]any{"from_port": 5432, "to_port": 5432, "protocol": "tcp", "cidr_blocks": []any{}, "ipv6_cidr_blocks": []any{},
			"security_groups": []any{"sg-0live"}, "self": false}}},
		unknown: map[string]any{"id": true}}
	db := res{addr: "aws_instance.db", actions: []string{"create"}, values: map[string]any{"subnet_id": "subnet-0live",
		"tags": map[string]any{"Name": "db-1", "crown-jewel": "true"}},
		unknown: map[string]any{"id": true, "vpc_security_group_ids": true, "public_ip": true, "private_ip": true},
		refs:    map[string][]string{"vpc_security_group_ids": {"aws_security_group.db.id", "aws_security_group.db"}}}
	plan := planOf(t, nil, []res{sg, db})

	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "security group sg-0live is let into sg-planned:aws_security_group.db on tcp/5432") {
		t.Errorf("plan alone: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	r = verdictLive(t, plan, sharedWeb(t, []any{perm(443, "0.0.0.0/0")}, true))
	if got := routes(r); !has(got, "introduced: web-1 -> db-1") || r.Incomplete != "" {
		t.Errorf("against the account: routes %v, incomplete %q - web-1 faces the internet and is in the group let in", got, r.Incomplete)
	}
}

// A group the live read does not hold - another Region, another account, one deleted - is
// outside both, and said to be.
func TestAGroupTheAccountDoesNotHold(t *testing.T) {
	rule := res{addr: "aws_security_group_rule.ssh", actions: []string{"create"}, values: map[string]any{"type": "ingress",
		"security_group_id": "sg-0elsewhere", "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}},
		unknown: map[string]any{"id": true}}
	r := verdictLive(t, planOf(t, adminRole(), with(adminRole(), rule)), sharedWeb(t, nil, true))
	if !strings.Contains(r.Incomplete, "security group sg-0elsewhere is opened to the internet on tcp/22, and the account read live does not hold it") {
		t.Errorf("incomplete = %q", r.Incomplete)
	}
}

// A route the plan gives a subnet another configuration manages: web-1 is in it.
func TestRoutingASharedSubnetToTheInternet(t *testing.T) {
	planned := []res{
		{addr: "aws_route_table.public", actions: []string{"create"}, values: map[string]any{"route": []any{
			map[string]any{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-0live"}}}, unknown: map[string]any{"id": true}},
		{addr: "aws_route_table_association.web", actions: []string{"create"}, values: map[string]any{"subnet_id": "subnet-0live"},
			unknown: map[string]any{"id": true, "route_table_id": true},
			refs:    map[string][]string{"route_table_id": {"aws_route_table.public.id", "aws_route_table.public"}}},
	}
	plan := planOf(t, adminRole(), with(adminRole(), planned...))
	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "subnet subnet-0live is routed to the internet") {
		t.Errorf("plan alone: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	r = verdictLive(t, plan, sharedWeb(t, []any{perm(22, "0.0.0.0/0")}, false))
	if !has(routes(r), "introduced: web-1 -> web -> account-admin (effective)") || r.Incomplete != "" {
		t.Errorf("against the account: routes %v, incomplete %q - web-1's subnet now routes to the internet gateway", routes(r), r.Incomplete)
	}

	// The same, through a route added to the table the subnet already uses.
	add := res{addr: "aws_route.default", actions: []string{"create"}, values: map[string]any{"route_table_id": "rtb-0live",
		"destination_cidr_block": "0.0.0.0/0", "gateway_id": "igw-0live"}, unknown: map[string]any{"id": true}}
	plan = planOf(t, adminRole(), with(adminRole(), add))
	if r := verdict(t, plan); !strings.Contains(r.Incomplete, "route table rtb-0live is given a route to the internet") {
		t.Errorf("plan alone: incomplete %q", r.Incomplete)
	}
	if r := verdictLive(t, plan, sharedWeb(t, []any{perm(22, "0.0.0.0/0")}, false)); !has(routes(r), "introduced: web-1 -> web -> account-admin (effective)") {
		t.Errorf("against the account: routes %v", routes(r))
	}

	// A route the plan adds beside the account's own leaves those standing: the table
	// already reaches the internet gateway, and the rule the plan adds opens SSH.
	peer := res{addr: "aws_route.partner", actions: []string{"create"}, values: map[string]any{"route_table_id": "rtb-0live",
		"destination_cidr_block": "10.9.0.0/16", "vpc_peering_connection_id": "pcx-0partner"}, unknown: map[string]any{"id": true}}
	rule := res{addr: "aws_security_group_rule.ssh", actions: []string{"create"}, values: map[string]any{"type": "ingress",
		"security_group_id": "sg-0live", "from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}},
		unknown: map[string]any{"id": true}}
	plan = planOf(t, adminRole(), with(adminRole(), peer, rule))
	if r := verdictLive(t, plan, sharedWeb(t, nil, true)); !has(routes(r), "introduced: web-1 -> web -> account-admin (effective)") {
		t.Errorf("a route beside the account's: %v", routes(r))
	}
}

// An instance the plan describes is as the plan describes it, not as the account last saw
// it: moved to a group that admits nothing, web-1 no longer faces the internet.
func TestThePlansInstanceIsTheOneJudged(t *testing.T) {
	inst := func(group string) res {
		return res{addr: "aws_instance.web", values: map[string]any{"id": "i-0live", "subnet_id": "subnet-0live",
			"vpc_security_group_ids": []any{group}, "private_ip": "10.0.1.10", "public_ip": "203.0.113.10", "tags": map[string]any{"Name": "web-1"}}}
	}
	quiet := res{addr: "aws_security_group.quiet", values: map[string]any{"id": "sg-0quiet", "name": "quiet", "ingress": []any{}}}
	moved := inst("sg-0quiet")
	moved.actions = []string{"update"}
	ch, err := terraform.New().ParseChange(strings.NewReader(planOf(t, []res{quiet, inst("sg-0live")}, []res{quiet, moved})),
		ingestion.Options{Account: account, EstateKnown: true, LiveFeeds: map[string][]byte{"cloudnet": sharedWeb(t, []any{perm(22, "0.0.0.0/0")}, true)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range ch.After {
		for _, n := range ev.Nodes {
			if n.Name == "web-1" && (n.Properties[ontology.PropNetworkExposed] != false || n.Properties[ontology.PropInternetExposed] == true) {
				t.Errorf("web-1 after the plan: %v", n.Properties)
			}
		}
	}
}
