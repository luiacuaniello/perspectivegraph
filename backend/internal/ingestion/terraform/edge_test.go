package terraform_test

import (
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/terraform"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The ways in a plan writes besides an instance's address: a load balancer, an ECS
// service, an API, and the network ACL in front of a subnet - and the ways between an EKS
// cluster and its account.

// A real plan, made offline: a load balancer in front of an instance, an ECS service with
// a public address, a REST API and two HTTP APIs in front of a function, every role account
// administrator, behind a network ACL that lets in what each of them listens on. And an EKS
// cluster whose pods take the same role, and whose access entry makes a role cluster-admin.
func TestTheWaysInOfARealPlan(t *testing.T) {
	raw, err := os.ReadFile("testdata/edge-create.json")
	if err != nil {
		t.Fatal(err)
	}
	r := verdict(t, string(raw))
	for _, want := range []string{
		"introduced: web -> app-1 -> app -> account-admin (effective)",
		"introduced: api -> app -> account-admin (effective)",
		"introduced: orders-api -> orders -> app -> account-admin (effective)",
		"introduced: http-api -> orders -> app -> account-admin (effective)",
		"introduced: quick-api -> orders -> app -> account-admin (effective)",
	} {
		if !has(routes(r), want) {
			t.Errorf("missing %q in %v", want, routes(r))
		}
	}
	if r.Incomplete != "" {
		t.Errorf("incomplete = %q: every identifier the plan leaves unknown is one it names", r.Incomplete)
	}

	ch, err := terraform.New().ParseChange(strings.NewReader(string(raw)), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	sa := ingestion.KubeID(ontology.LabelServiceAccount, "prod", "prod/api")
	role := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::planned:role/app")
	deployer := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::planned:role/deployer")
	admin := ingestion.KubeID(ontology.LabelIAMRole, "prod", "perspectivegraph:cluster-admin")
	found := map[string]bool{}
	for _, ev := range ch.After {
		for _, e := range ev.Edges {
			found[e.From+" -> "+e.To] = true
		}
	}
	if !found[sa+" -> "+role] {
		t.Error("the Pod Identity association: prod/api takes the role app")
	}
	if !found[deployer+" -> "+admin] {
		t.Error("the access entry: deployer is cluster-admin of prod")
	}
}

// webACL is the network ACL in front of web-1's subnet, letting in the ports given.
func webACL(ports ...int) res {
	var entries []any
	for i, port := range ports {
		entries = append(entries, map[string]any{"rule_no": 100 + 10*i, "action": "allow", "protocol": "tcp",
			"from_port": port, "to_port": port, "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": ""})
	}
	return res{addr: "aws_network_acl.web", values: map[string]any{"id": "acl-0a1", "subnet_ids": []any{"subnet-0a1"}, "ingress": entries}}
}

// A network ACL is the last word on what reaches a subnet. SSH opened in the group passes
// an ACL that lets it in, and not one that does not.
func TestANetworkACLDecidesWhatReachesASubnet(t *testing.T) {
	closed := []any{ingress(443, "10.0.0.0/8")}
	open := map[string]any{"id": "sg-0a1", "name": "web", "ingress": []any{ingress(22, "0.0.0.0/0")}}
	route := "introduced: web-1 -> web -> account-admin (effective)"

	prior := append(webTier(closed, "igw-0a1", true), webACL(443))
	if got := routes(verdict(t, planOf(t, prior, changed(prior, "aws_security_group.web", open)))); len(got) != 0 {
		t.Errorf("an ACL that lets in only 443: %v", got)
	}
	prior = append(webTier(closed, "igw-0a1", true), webACL(443, 22))
	if got := routes(verdict(t, planOf(t, prior, changed(prior, "aws_security_group.web", open)))); !has(got, route) {
		t.Errorf("an ACL that lets SSH in: %v", got)
	}
	// And the ACL is what the plan opens: the group was open, the ACL let in only 443.
	prior = append(webTier([]any{ingress(22, "0.0.0.0/0")}, "igw-0a1", true), webACL(443))
	opened := webACL(443, 22)
	opened.actions = []string{"update"}
	if got := routes(verdict(t, planOf(t, prior, with(prior[:len(prior)-1], opened)))); !has(got, route) {
		t.Errorf("the plan opens the ACL: %v", got)
	}
}

// A rule the plan adds to an ACL another configuration manages, and one it deletes from it.
func TestRulesOnASharedNetworkACL(t *testing.T) {
	allowSSH := res{addr: "aws_network_acl_rule.ssh", actions: []string{"create"}, values: map[string]any{"network_acl_id": "acl-0live",
		"rule_number": 90, "egress": false, "protocol": "tcp", "rule_action": "allow", "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22},
		unknown: map[string]any{"id": true}}
	plan := planOf(t, adminRole(), with(adminRole(), allowSSH))
	route := "introduced: web-1 -> web -> account-admin (effective)"

	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "network ACL acl-0live lets in more from the internet (tcp/22)") {
		t.Errorf("plan alone: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	r = verdictLive(t, plan, sharedWeb(t, []any{perm(22, "0.0.0.0/0")}, true, 443))
	if !has(routes(r), route) || r.Incomplete != "" {
		t.Errorf("against the account, whose ACL let in only 443: routes %v, incomplete %q", routes(r), r.Incomplete)
	}

	// The account's ACL denies SSH first, through a rule this configuration wrote, and lets
	// in everything after it. The plan deletes the rule.
	denySSH := res{addr: "aws_network_acl_rule.no_ssh", values: map[string]any{"network_acl_id": "acl-0live", "rule_number": 90,
		"egress": false, "protocol": "tcp", "rule_action": "deny", "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22}}
	live := sharedWebMap([]any{perm(22, "0.0.0.0/0")}, true)
	live["network_acls"] = []any{map[string]any{"NetworkAclId": "acl-0live", "Entries": []any{
		map[string]any{"RuleNumber": 90, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "deny", "Protocol": "6",
			"PortRange": map[string]any{"From": 22, "To": 22}},
		map[string]any{"RuleNumber": 100, "Egress": false, "CidrBlock": "0.0.0.0/0", "RuleAction": "allow", "Protocol": "-1"},
	}}}
	if r := verdictLive(t, planOf(t, with(adminRole(), denySSH), adminRole()), marshal(t, live)); !has(routes(r), route) {
		t.Errorf("the deny the plan deletes: %v", routes(r))
	}
	if r := verdictLive(t, planOf(t, with(adminRole(), denySSH), with(adminRole(), denySSH)), marshal(t, live)); len(r.Blocking) != 0 {
		t.Errorf("the deny the plan keeps: %v", routes(r))
	}
	// The plan turns the same rule number into an allow: AWS keeps one entry per number.
	turned := denySSH
	turned.actions = []string{"update"}
	turned.values = map[string]any{"network_acl_id": "acl-0live", "rule_number": 90, "egress": false, "protocol": "tcp",
		"rule_action": "allow", "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22}
	if r := verdictLive(t, planOf(t, with(adminRole(), denySSH), with(adminRole(), turned)), marshal(t, live)); !has(routes(r), route) {
		t.Errorf("rule 90 turned into an allow: %v", routes(r))
	}

	// An ACL this configuration manages whole: what it writes is the ACL, and the deny the
	// account still shows from before is gone.
	managed := func(entries ...any) res {
		return res{addr: "aws_network_acl.web", values: map[string]any{"id": "acl-0live", "subnet_ids": []any{"subnet-0live"}, "ingress": entries}}
	}
	allowAll := map[string]any{"rule_no": 100, "action": "allow", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": ""}
	denyRule := map[string]any{"rule_no": 90, "action": "deny", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_block": "0.0.0.0/0", "ipv6_cidr_block": ""}
	rewritten := managed(allowAll)
	rewritten.actions = []string{"update"}
	if r := verdictLive(t, planOf(t, with(adminRole(), managed(denyRule, allowAll)), with(adminRole(), rewritten)), marshal(t, live)); !has(routes(r), route) {
		t.Errorf("the managed ACL without its deny: %v", routes(r))
	}

	// An ACL the configuration manages through rule resources, not entries of its own: its
	// ingress attribute is what AWS had when the plan was made, the deny still in it.
	viaRules := func(entries ...any) res {
		return res{addr: "aws_network_acl.web", values: map[string]any{"id": "acl-0a1", "subnet_ids": []any{"subnet-0a1"}, "ingress": entries}}
	}
	allowRule := res{addr: "aws_network_acl_rule.all", values: map[string]any{"network_acl_id": "acl-0a1", "rule_number": 100,
		"egress": false, "protocol": "-1", "rule_action": "allow", "cidr_block": "0.0.0.0/0"}}
	denyRule22 := res{addr: "aws_network_acl_rule.no_ssh", values: map[string]any{"network_acl_id": "acl-0a1", "rule_number": 90,
		"egress": false, "protocol": "tcp", "rule_action": "deny", "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22}}
	base := webTier([]any{ingress(22, "0.0.0.0/0")}, "igw-0a1", true)
	stale := viaRules(denyRule, allowAll)
	priorRules := with(base, stale, allowRule, denyRule22)
	if r := verdict(t, planOf(t, priorRules, with(base, stale, allowRule))); !has(routes(r), route) {
		t.Errorf("the deny the plan deletes, still in the ACL's attribute: %v", routes(r))
	}
	if r := verdict(t, planOf(t, priorRules, priorRules)); len(r.Blocking) != 0 {
		t.Errorf("the deny the plan keeps: %v", routes(r))
	}

	// The account's subnet, put under an ACL the plan creates that lets SSH in.
	open := res{addr: "aws_network_acl.open", actions: []string{"create"}, values: map[string]any{"subnet_ids": []any{"subnet-0live"},
		"ingress": []any{allowAll}}, unknown: map[string]any{"id": true}}
	if r := verdictLive(t, planOf(t, adminRole(), with(adminRole(), open)), sharedWeb(t, []any{perm(22, "0.0.0.0/0")}, true, 443)); !has(routes(r), route) {
		t.Errorf("the subnet under the new ACL: %v", routes(r))
	}
}

const edgeLB = "arn:aws:elasticloadbalancing:eu-north-1:" + account + ":loadbalancer/app/edge/0abc"
const edgeTG = "arn:aws:elasticloadbalancing:eu-north-1:" + account + ":targetgroup/web-tg/0def"

// withEdge is the account with a load balancer in front of web-1's subnet: internet-facing,
// its group open on the ports given, forwarding on port 80 to web-tg, whose targets are the
// ones given. web-1's own group lets in nothing from the internet.
func withEdge(t *testing.T, targets []any, open ...int) []byte {
	t.Helper()
	live := sharedWebMap([]any{perm(8080, "10.0.0.0/8")}, true)
	var lbIngress []any
	for _, port := range open {
		lbIngress = append(lbIngress, perm(port, "0.0.0.0/0"))
	}
	live["security_groups"] = append(live["security_groups"].([]any),
		map[string]any{"GroupId": "sg-0lb", "GroupName": "edge", "IpPermissions": lbIngress})
	live["load_balancers"] = []any{map[string]any{"LoadBalancerArn": edgeLB, "LoadBalancerName": "edge", "Type": "application",
		"Scheme": "internet-facing", "IpAddressType": "ipv4", "SecurityGroups": []any{"sg-0lb"},
		"AvailabilityZones": []any{map[string]any{"SubnetId": "subnet-0live"}},
		"Listeners":         []any{map[string]any{"Protocol": "HTTP", "Port": 80}},
		"TargetGroups": []any{map[string]any{"TargetGroupArn": edgeTG, "TargetType": "instance", "Protocol": "HTTP", "Port": 8080,
			"Targets": targets}}}}
	return marshal(t, live)
}

// A listener this configuration adds to a load balancer another one manages, forwarding to
// web-1. Whether the load balancer faces the internet is the account's to say.
func TestAListenerOnASharedLoadBalancer(t *testing.T) {
	plan := planOf(t, adminRole(), with(adminRole(),
		res{addr: "aws_lb_target_group.web", actions: []string{"create"}, values: map[string]any{"name": "web", "port": 8080, "protocol": "HTTP",
			"target_type": "instance"}, unknown: map[string]any{"arn": true, "id": true}},
		res{addr: "aws_lb_target_group_attachment.web", actions: []string{"create"}, values: map[string]any{"target_id": "i-0live", "port": 8080},
			unknown: map[string]any{"target_group_arn": true, "id": true},
			refs:    map[string][]string{"target_group_arn": {"aws_lb_target_group.web.arn", "aws_lb_target_group.web"}}},
		res{addr: "aws_lb_listener.admin", actions: []string{"create"}, values: map[string]any{"load_balancer_arn": edgeLB, "port": 8443,
			"protocol": "HTTP", "default_action": []any{map[string]any{"type": "forward"}}},
			unknown: map[string]any{"arn": true, "id": true, "default_action": []any{map[string]any{"target_group_arn": true}}},
			refs:    map[string][]string{"default_action": {"aws_lb_target_group.web.arn", "aws_lb_target_group.web"}}},
	))
	route := "introduced: edge -> web-1 -> web -> account-admin (effective)"

	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "load balancer edge gets a listener or a target group") {
		t.Errorf("plan alone: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	r = verdictLive(t, plan, withEdge(t, []any{}, 80, 8443))
	if !has(routes(r), route) || r.Incomplete != "" {
		t.Errorf("against the account: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	// The server's graph says the load balancer faces the internet: what the plan holds of
	// it - a listener - must not say otherwise.
	if r := verdictFeeds(t, plan, map[string][]byte{"cloudnet": withEdge(t, []any{}, 80, 8443)}, false); !has(routes(r), route) {
		t.Errorf("against the graph: routes %v", routes(r))
	}
	// A listener rule on the account's own listener does the same.
	rule := planOf(t, adminRole(), with(adminRole(),
		res{addr: "aws_lb_target_group.web", actions: []string{"create"}, values: map[string]any{"name": "web", "port": 8080, "protocol": "HTTP",
			"target_type": "instance"}, unknown: map[string]any{"arn": true, "id": true}},
		res{addr: "aws_lb_target_group_attachment.web", actions: []string{"create"}, values: map[string]any{"target_id": "i-0live", "port": 8080},
			unknown: map[string]any{"target_group_arn": true, "id": true},
			refs:    map[string][]string{"target_group_arn": {"aws_lb_target_group.web.arn", "aws_lb_target_group.web"}}},
		res{addr: "aws_lb_listener_rule.admin", actions: []string{"create"}, values: map[string]any{
			"listener_arn": strings.Replace(edgeLB, ":loadbalancer/", ":listener/", 1) + "/l1", "priority": 10,
			"action": []any{map[string]any{"type": "forward"}}},
			unknown: map[string]any{"arn": true, "id": true, "action": []any{map[string]any{"target_group_arn": true}}},
			refs:    map[string][]string{"action": {"aws_lb_target_group.web.arn", "aws_lb_target_group.web"}}},
	))
	if r := verdictLive(t, rule, withEdge(t, []any{}, 80)); !has(routes(r), route) {
		t.Errorf("a listener rule: %v", routes(r))
	}
	// Its group admits nothing from the internet: no way in. (Which listener forwards to
	// which target group is not read, here as from the account: a load balancer the
	// internet reaches on any port reaches every target it forwards to.)
	if r := verdictLive(t, plan, withEdge(t, []any{})); len(r.Blocking) != 0 {
		t.Errorf("a group that admits nothing: %v", routes(r))
	}
}

// A target registered in a group of the account's load balancer.
func TestATargetInASharedTargetGroup(t *testing.T) {
	attach := res{addr: "aws_lb_target_group_attachment.web", actions: []string{"create"}, values: map[string]any{
		"target_group_arn": edgeTG, "target_id": "i-0live", "port": 8080}, unknown: map[string]any{"id": true}}
	plan := planOf(t, adminRole(), with(adminRole(), attach))

	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "target group "+edgeTG+" gains target i-0live") {
		t.Errorf("plan alone: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	r = verdictLive(t, plan, withEdge(t, []any{}, 80))
	if !has(routes(r), "introduced: edge -> web-1 -> web -> account-admin (effective)") || r.Incomplete != "" {
		t.Errorf("against the account: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
}

// A load balancer the configuration manages, made internet-facing. Its targets are the ones
// an Auto Scaling group registered - not in the plan, and in the account.
func TestATargetGroupKeepsTheAccountsTargets(t *testing.T) {
	lb := func(internal bool) res {
		return res{addr: "aws_lb.edge", values: map[string]any{"arn": edgeLB, "name": "edge", "load_balancer_type": "application",
			"internal": internal, "security_groups": []any{"sg-0lb"}, "subnets": []any{"subnet-0live"}}}
	}
	tg := res{addr: "aws_lb_target_group.web", values: map[string]any{"arn": edgeTG, "name": "web-tg", "port": 8080, "protocol": "HTTP", "target_type": "instance"}}
	listener := res{addr: "aws_lb_listener.http", values: map[string]any{"arn": edgeLB + "/l1", "load_balancer_arn": edgeLB, "port": 80, "protocol": "HTTP",
		"default_action": []any{map[string]any{"type": "forward", "target_group_arn": edgeTG}}}}
	public := lb(false)
	public.actions = []string{"update"}
	plan := planOf(t, with(adminRole(), lb(true), tg, listener), with(adminRole(), public, tg, listener))

	asg := []any{map[string]any{"Id": "i-0live", "Port": 8080}}
	if r := verdictLive(t, plan, withEdge(t, asg, 80)); !has(routes(r), "introduced: edge -> web-1 -> web -> account-admin (effective)") {
		t.Errorf("routes %v: web-1 is registered in web-tg, in the account", routes(r))
	}
}

// An ECS service this configuration launches into a group another one manages.
func TestAnECSServiceInASharedGroup(t *testing.T) {
	taskDef := res{addr: "aws_ecs_task_definition.api", actions: []string{"create"}, values: map[string]any{"family": "api",
		"task_role_arn": "arn:aws:iam::" + account + ":role/web"}, unknown: map[string]any{"arn": true}}
	svc := res{addr: "aws_ecs_service.api", actions: []string{"create"}, values: map[string]any{"name": "api",
		"cluster":               "arn:aws:ecs:eu-north-1:" + account + ":cluster/main",
		"network_configuration": []any{map[string]any{"subnets": []any{"subnet-0live"}, "security_groups": []any{"sg-0live"}, "assign_public_ip": true}}},
		unknown: map[string]any{"id": true, "task_definition": true},
		refs:    map[string][]string{"task_definition": {"aws_ecs_task_definition.api.arn", "aws_ecs_task_definition.api"}}}
	plan := planOf(t, adminRole(), with(adminRole(), taskDef, svc))
	route := "introduced: api -> web -> account-admin (effective)"

	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "ECS service api: its security group sg-0live has rules the configuration does not hold") {
		t.Errorf("plan alone: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	r = verdictLive(t, plan, sharedWeb(t, []any{perm(8080, "0.0.0.0/0")}, true))
	if !has(routes(r), route) || r.Incomplete != "" {
		t.Errorf("against the account: routes %v, incomplete %q", routes(r), r.Incomplete)
	}

	// A task definition kept elsewhere: the role its tasks hold is not in the plan.
	elsewhere := svc
	elsewhere.values = map[string]any{"name": "api", "cluster": "main", "task_definition": "legacy:3",
		"network_configuration": svc.values["network_configuration"]}
	elsewhere.unknown, elsewhere.refs = map[string]any{"id": true}, nil
	plan = planOf(t, adminRole(), with(adminRole(), elsewhere))
	if r := verdict(t, plan); !strings.Contains(r.Incomplete, "aws_ecs_service.api: its task definition legacy:3 is outside the plan") {
		t.Errorf("incomplete = %q", r.Incomplete)
	}
	// The account runs the service already, and knows the role its tasks hold.
	svcARN := "arn:aws:ecs:eu-north-1:" + account + ":service/main/api"
	live := sharedWebMap([]any{perm(8080, "0.0.0.0/0")}, true)
	live["ecs_services"] = []any{map[string]any{"serviceArn": svcARN, "serviceName": "api", "clusterArn": "arn:aws:ecs:eu-north-1:" + account + ":cluster/main",
		"taskRoleArn": "arn:aws:iam::" + account + ":role/web", "assignPublicIp": "ENABLED", "securityGroups": []any{"sg-0live"}, "subnets": []any{"subnet-0live"}}}
	if r := verdictLive(t, plan, marshal(t, live)); r.Incomplete != "" {
		t.Errorf("incomplete = %q: the account holds the service", r.Incomplete)
	}
	ch, err := terraform.New().ParseChange(strings.NewReader(plan), ingestion.Options{Account: account, EstateKnown: true,
		LiveFeeds: map[string][]byte{"cloudnet": marshal(t, live)}})
	if err != nil {
		t.Fatal(err)
	}
	holds := false
	for _, ev := range ch.After {
		for _, e := range ev.Edges {
			holds = holds || (e.From == ontology.NewID(ontology.LabelContainer, svcARN) && e.To == ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::"+account+":role/web"))
		}
	}
	if !holds {
		t.Error("the service's tasks hold the role the account says they do")
	}
}

const ordersAPI = "a1b2c3d4e5"

// A route this configuration adds to an API another one manages. Whether the API is
// deployed, and what its resource policy allows, is the account's to say.
func TestARouteOnASharedAPI(t *testing.T) {
	fnARN := "arn:aws:lambda:eu-north-1:" + account + ":function:orders"
	fn := res{addr: "aws_lambda_function.orders", values: map[string]any{"function_name": "orders", "arn": fnARN,
		"role":       "arn:aws:iam::" + account + ":role/web",
		"invoke_arn": "arn:aws:apigateway:eu-north-1:lambda:path/2015-03-31/functions/" + fnARN + "/invocations"}}
	prior := with(adminRole(), fn)
	added := []res{
		{addr: "aws_api_gateway_resource.export", actions: []string{"create"}, values: map[string]any{"rest_api_id": ordersAPI,
			"parent_id": "root0", "path_part": "export"}, unknown: map[string]any{"id": true, "path": true}},
		{addr: "aws_api_gateway_method.export", actions: []string{"create"}, values: map[string]any{"rest_api_id": ordersAPI,
			"http_method": "GET", "authorization": "NONE"}, unknown: map[string]any{"resource_id": true},
			refs: map[string][]string{"resource_id": {"aws_api_gateway_resource.export.id", "aws_api_gateway_resource.export"}}},
		{addr: "aws_api_gateway_integration.export", actions: []string{"create"}, values: map[string]any{"rest_api_id": ordersAPI,
			"http_method": "GET", "type": "AWS_PROXY", "uri": fn.values["invoke_arn"]}, unknown: map[string]any{"resource_id": true},
			refs: map[string][]string{"resource_id": {"aws_api_gateway_resource.export.id", "aws_api_gateway_resource.export"}}},
	}
	plan := planOf(t, prior, with(prior, added...))
	route := "introduced: orders-api -> orders -> web -> account-admin (effective)"

	r := verdict(t, plan)
	if len(r.Blocking) != 0 || !strings.Contains(r.Incomplete, "API "+ordersAPI+" gets a route that asks for nothing (GET /export)") {
		t.Errorf("plan alone: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	api := func(stages []any) []byte {
		return marshal(t, map[string]any{"account": account, "region": "eu-north-1", "rest_apis": []any{map[string]any{
			"id": ordersAPI, "name": "orders-api", "endpointTypes": []any{"REGIONAL"}, "stages": stages,
			"methods": []any{map[string]any{"path": "/orders", "httpMethod": "GET", "authorizationType": "AWS_IAM"}}}}})
	}
	feeds := map[string][]byte{"cloudnet": sharedWeb(t, nil, true), "apigateway": api([]any{"prod"})}
	r = verdictFeeds(t, plan, feeds, true)
	if !has(routes(r), route) || r.Incomplete != "" {
		t.Errorf("against the account: routes %v, incomplete %q", routes(r), r.Incomplete)
	}
	// Not deployed to any stage: nothing answers - until the plan deploys it.
	feeds["apigateway"] = api([]any{})
	if r := verdictFeeds(t, plan, feeds, true); len(r.Blocking) != 0 {
		t.Errorf("an API on no stage: %v", routes(r))
	}
	stage := res{addr: "aws_api_gateway_stage.prod", actions: []string{"create"}, values: map[string]any{"rest_api_id": ordersAPI, "stage_name": "prod"},
		unknown: map[string]any{"id": true}}
	if r := verdictFeeds(t, planOf(t, prior, with(prior, append(added, stage)...)), feeds, true); !has(routes(r), route) {
		t.Errorf("deployed by the plan: %v", routes(r))
	}
}
