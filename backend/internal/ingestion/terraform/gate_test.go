package terraform_test

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/terraform"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The gate's question asked of plans that change something already deployed: the prior
// state carries real identifiers, and the comparison is between the estate as the plan
// finds it and as it would leave it. Each plan is built here in the documented JSON shape,
// one resource at a time, so each case says exactly what changes.

const account = "111122223333"

// res is a resource instance in one state of a plan.
type res struct {
	addr    string
	values  map[string]any
	unknown map[string]any      // planned state only: known after apply
	refs    map[string][]string // the configuration's references, by attribute
	actions []string            // planned state only; default no-op
}

var addrParts = regexp.MustCompile(`^(?:(data)\.)?([a-z0-9_]+)\.([A-Za-z0-9_-]+)(\[.*\])?$`)

func resourceJSON(r res) map[string]any {
	m := addrParts.FindStringSubmatch(r.addr)
	mode := "managed"
	if m[1] == "data" {
		mode = "data"
	}
	out := map[string]any{"address": r.addr, "mode": mode, "type": m[2], "name": m[3], "values": r.values}
	if m[4] != "" {
		var idx any
		_ = json.Unmarshal([]byte(strings.Trim(m[4], "[]")), &idx)
		out["index"] = idx
	}
	return out
}

// planOf writes a plan: the prior state, the planned one, and the configuration's
// references, which the planned resources declare.
func planOf(t *testing.T, prior, planned []res) string {
	t.Helper()
	var pr, pl, changes, cfg []any
	for _, r := range prior {
		pr = append(pr, resourceJSON(r))
	}
	seenCfg := map[string]bool{}
	for _, r := range planned {
		pl = append(pl, resourceJSON(r))
		actions := r.actions
		if actions == nil {
			actions = []string{"no-op"}
		}
		unknown := r.unknown
		if unknown == nil {
			unknown = map[string]any{}
		}
		changes = append(changes, map[string]any{"address": r.addr, "change": map[string]any{"actions": actions, "after_unknown": unknown}})
		m := addrParts.FindStringSubmatch(r.addr)
		base := m[2] + "." + m[3]
		if seenCfg[base] {
			continue
		}
		seenCfg[base] = true
		exprs := map[string]any{}
		for attr, refs := range r.refs {
			exprs[attr] = map[string]any{"references": refs}
		}
		cfg = append(cfg, map[string]any{"address": base, "mode": "managed", "type": m[2], "name": m[3], "expressions": exprs})
	}
	doc := map[string]any{
		"format_version":   "1.2",
		"timestamp":        "2026-10-07T10:00:00Z",
		"planned_values":   map[string]any{"root_module": map[string]any{"resources": pl}},
		"prior_state":      map[string]any{"values": map[string]any{"root_module": map[string]any{"resources": pr}}},
		"resource_changes": changes,
		"configuration":    map[string]any{"provider_config": map[string]any{"aws": map[string]any{"expressions": map[string]any{"region": map[string]any{"constant_value": "eu-north-1"}}}}, "root_module": map[string]any{"resources": cfg}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// verdict runs the plan through the gate's comparison, with nothing else in the estate:
// what the plan alone says.
func verdict(t *testing.T, plan string) impact.Result {
	t.Helper()
	ch, err := terraform.New().ParseChange(strings.NewReader(plan), ingestion.Options{RepoSlug: "acme/infra", CommitSHA: "c0ffee"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := impact.Evaluate(context.Background(), impact.Input{Base: graph.Snapshot{}, BaseChange: ch.Before, Change: ch.After,
		Unknown: ch.Unknown, Outside: ch.Outside, Slug: "acme/infra", SHA: "c0ffee"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func routes(r impact.Result) []string {
	var out []string
	for _, p := range r.Blocking {
		var names []string
		for _, n := range p.Nodes {
			names = append(names, n.Name)
		}
		out = append(out, string(p.Change)+": "+strings.Join(names, " -> "))
	}
	return out
}

func has(routes []string, want string) bool {
	for _, r := range routes {
		if r == want {
			return true
		}
	}
	return false
}

// A deployed web tier: an instance with a public address in a subnet routed to an internet
// gateway, holding a role that is account administrator, and a group that lets in nothing
// from the internet. The cases change one thing each.
func webTier(sgIngress []any, subnetRoute string, adminAttached bool) (prior []res) {
	routes := []any{map[string]any{"cidr_block": "10.0.0.0/16", "gateway_id": "local"}}
	if subnetRoute != "" {
		routes = append(routes, map[string]any{"cidr_block": "0.0.0.0/0", "gateway_id": subnetRoute})
	}
	prior = []res{
		{addr: "aws_route_table.main", values: map[string]any{"id": "rtb-0a1", "route": routes}},
		{addr: "aws_route_table_association.web", values: map[string]any{"id": "rtbassoc-1", "subnet_id": "subnet-0a1", "route_table_id": "rtb-0a1"}},
		{addr: "aws_subnet.web", values: map[string]any{"id": "subnet-0a1", "map_public_ip_on_launch": false}},
		{addr: "aws_security_group.web", values: map[string]any{"id": "sg-0a1", "name": "web", "ingress": sgIngress}},
		{addr: "aws_iam_role.web", values: map[string]any{"name": "web", "path": "/", "arn": "arn:aws:iam::" + account + ":role/web",
			"assume_role_policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}},
		{addr: "aws_iam_instance_profile.web", values: map[string]any{"name": "web", "arn": "arn:aws:iam::" + account + ":instance-profile/web", "role": "web"}},
		{addr: "aws_instance.web", values: map[string]any{"id": "i-0a1", "subnet_id": "subnet-0a1", "vpc_security_group_ids": []any{"sg-0a1"},
			"iam_instance_profile": "web", "private_ip": "10.0.1.10", "public_ip": "203.0.113.10", "associate_public_ip_address": true,
			"tags": map[string]any{"Name": "web-1"}}},
	}
	if adminAttached {
		prior = append(prior, res{addr: "aws_iam_role_policy_attachment.admin", values: map[string]any{"id": "web-x", "role": "web",
			"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}})
	}
	return prior
}

func ingress(port int, cidr string) map[string]any {
	return map[string]any{"from_port": port, "to_port": port, "protocol": "tcp", "cidr_blocks": []any{cidr},
		"ipv6_cidr_blocks": []any{}, "security_groups": []any{}, "self": false}
}

// changed returns the prior state as the plan would leave it: the resource at addr
// replaced by its planned values, marked as an update.
func changed(prior []res, addr string, values map[string]any) []res {
	out := make([]res, 0, len(prior))
	for _, r := range prior {
		if r.addr == addr {
			r.values = values
			r.actions = []string{"update"}
		}
		out = append(out, r)
	}
	return out
}

func TestOpeningSSHOnAnAdminInstanceIsBlocked(t *testing.T) {
	closed := []any{ingress(443, "10.0.0.0/8")}
	prior := webTier(closed, "igw-0a1", true)
	open := map[string]any{"id": "sg-0a1", "name": "web", "ingress": []any{ingress(443, "10.0.0.0/8"), ingress(22, "0.0.0.0/0")}}
	r := verdict(t, planOf(t, prior, changed(prior, "aws_security_group.web", open)))
	if got := routes(r); !has(got, "introduced: web-1 -> web -> account-admin (effective)") {
		t.Errorf("routes = %v, want the route the open SSH port makes", got)
	}
	// The group exists already, and the plan alone cannot say what else uses it: the route
	// it found stands, and the verdict says what it could not see.
	if !r.Analysed || !strings.Contains(r.Incomplete, "outside the plan - security group sg-0a1 is opened to the internet on tcp/22") {
		t.Errorf("analysed=%v incomplete=%q", r.Analysed, r.Incomplete)
	}
}

// The same group change in a subnet with no route to an internet gateway: the security
// group is open and nothing from the internet reaches it. This is the false positive a
// rule that reads security groups alone would raise.
func TestOpeningSSHInAPrivateSubnetIsNot(t *testing.T) {
	closed := []any{ingress(443, "10.0.0.0/8")}
	prior := webTier(closed, "", true)
	open := map[string]any{"id": "sg-0a1", "name": "web", "ingress": []any{ingress(22, "0.0.0.0/0")}}
	r := verdict(t, planOf(t, prior, changed(prior, "aws_security_group.web", open)))
	if got := routes(r); len(got) != 0 {
		t.Errorf("routes = %v, want none: no internet-gateway route", got)
	}
	if !r.Analysed {
		t.Error("the plan describes the instance; it is analysed")
	}
}

// Attaching AdministratorAccess to the role of an instance the internet already reaches:
// the route to account administrator is the plan's doing.
func TestAttachingAdministratorToAnExposedRoleIsBlocked(t *testing.T) {
	prior := webTier([]any{ingress(443, "0.0.0.0/0")}, "igw-0a1", false)
	planned := append(append([]res(nil), prior...), res{addr: "aws_iam_role_policy_attachment.admin", actions: []string{"create"},
		values:  map[string]any{"role": "web", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
		unknown: map[string]any{"id": true}})
	r := verdict(t, planOf(t, prior, planned))
	if got := routes(r); !has(got, "introduced: web-1 -> web -> account-admin (effective)") {
		t.Errorf("routes = %v", got)
	}
}

// A plan that changes nothing: the routes through its resources were there before it.
func TestAPlanThatChangesNothingIsClean(t *testing.T) {
	prior := webTier([]any{ingress(443, "0.0.0.0/0")}, "igw-0a1", true)
	r := verdict(t, planOf(t, prior, prior))
	if got := routes(r); len(got) != 0 {
		t.Errorf("routes = %v, want none", got)
	}
	if r.Preexisting == 0 {
		t.Error("the existing route through the plan's assets is preexisting")
	}
	if !r.Analysed || !r.Reachable {
		t.Errorf("analysed=%v reachable=%v", r.Analysed, r.Reachable)
	}
	// Its groups exist and stay as they were: nothing it changes reaches beyond it.
	if r.Incomplete != "" {
		t.Errorf("incomplete = %q, want nothing: the plan opens nothing", r.Incomplete)
	}
}

// A bucket the plan opens to anyone holds sensitive data: the route is the bucket itself.
// The same plan with the bucket's Block Public Access restricting public policies is not.
func TestABucketPolicyOpenToAnyone(t *testing.T) {
	bucket := res{addr: "aws_s3_bucket.exports", values: map[string]any{"bucket": "acme-exports", "arn": "arn:aws:s3:::acme-exports",
		"tags": map[string]any{"crown-jewel": "true"}}}
	public := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::acme-exports/*"}]}`
	policy := res{addr: "aws_s3_bucket_policy.exports", actions: []string{"create"}, values: map[string]any{"bucket": "acme-exports", "policy": public},
		unknown: map[string]any{"id": true}}
	r := verdict(t, planOf(t, []res{bucket}, []res{bucket, policy}))
	if !r.Analysed || len(r.Blocking) == 0 {
		t.Errorf("a public policy on a sensitive bucket must block: %v", routes(r))
	}

	block := res{addr: "aws_s3_bucket_public_access_block.exports", values: map[string]any{"bucket": "acme-exports",
		"block_public_acls": true, "ignore_public_acls": true, "block_public_policy": true, "restrict_public_buckets": true}}
	r = verdict(t, planOf(t, []res{bucket, block}, []res{bucket, block, policy}))
	if got := routes(r); len(got) != 0 {
		t.Errorf("RestrictPublicBuckets keeps strangers out of a public policy: %v", got)
	}
}

// A policy built from a resource the same plan creates is known only once that resource
// exists. No route found through it is not a clean answer.
func TestAPolicyKnownOnlyAfterApplyLeavesTheVerdictIncomplete(t *testing.T) {
	bucket := res{addr: "aws_s3_bucket.exports", actions: []string{"create"}, values: map[string]any{"bucket": "acme-exports",
		"tags": map[string]any{"crown-jewel": "true"}}, unknown: map[string]any{"arn": true, "id": true}}
	policy := res{addr: "aws_s3_bucket_policy.exports", actions: []string{"create"}, values: map[string]any{},
		unknown: map[string]any{"bucket": true, "policy": true, "id": true},
		refs:    map[string][]string{"bucket": {"aws_s3_bucket.exports.id", "aws_s3_bucket.exports"}, "policy": {"aws_s3_bucket.exports.arn", "aws_s3_bucket.exports"}}}
	r := verdict(t, planOf(t, nil, []res{bucket, policy}))
	if len(r.Blocking) != 0 {
		t.Errorf("routes = %v: the policy is unknown, not public", routes(r))
	}
	if !strings.Contains(r.Incomplete, "acme-exports") {
		t.Errorf("incomplete = %q, want the bucket's policy named", r.Incomplete)
	}
}

// A function URL opened to anyone, on a function whose role can make itself administrator.
func TestOpeningAFunctionURLIsBlocked(t *testing.T) {
	role := res{addr: "aws_iam_role.fn", values: map[string]any{"name": "fn", "path": "/", "arn": "arn:aws:iam::" + account + ":role/fn",
		"assume_role_policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`}}
	grant := res{addr: "aws_iam_role_policy.fn", values: map[string]any{"name": "deploy", "role": "fn",
		"policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}`}}
	fn := res{addr: "aws_lambda_function.api", values: map[string]any{"function_name": "orders-api",
		"arn": "arn:aws:lambda:eu-north-1:" + account + ":function:orders-api", "role": "arn:aws:iam::" + account + ":role/fn"}}
	prior := []res{role, grant, fn}
	url := res{addr: "aws_lambda_function_url.api", actions: []string{"create"}, values: map[string]any{"function_name": "orders-api", "authorization_type": "NONE"},
		unknown: map[string]any{"function_url": true}}
	perm := func(name, action string) res {
		return res{addr: "aws_lambda_permission." + name, actions: []string{"create"}, values: map[string]any{"function_name": "orders-api",
			"principal": "*", "action": action, "statement_id": name, "function_url_auth_type": "NONE"}}
	}
	planned := []res{role, grant, fn, url, perm("url", "lambda:InvokeFunctionUrl"), perm("invoke", "lambda:InvokeFunction")}
	r := verdict(t, planOf(t, prior, planned))
	if got := routes(r); !has(got, "introduced: orders-api -> fn -> account-admin (effective)") {
		t.Errorf("routes = %v", got)
	}

	// Without the second grant a URL created now answers 403: Lambda's rule since
	// October 2025, which the lambda collector applies to a URL this plan creates.
	r = verdict(t, planOf(t, prior, planned[:5]))
	if got := routes(r); len(got) != 0 {
		t.Errorf("a new URL with only lambda:InvokeFunctionUrl is closed: %v", got)
	}
}

// The real plans: a whole stack created at once, and one built from a module.
func TestRealPlans(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	r := verdict(t, read("web-create.json"))
	for _, want := range []string{
		"introduced: web-1 -> web-role -> account-admin (effective)",
		"introduced: web-1 -> db-0",
		"introduced: web-1 -> db-1",
	} {
		if !has(routes(r), want) {
			t.Errorf("web plan: missing %q in %v", want, routes(r))
		}
	}
	if !strings.Contains(r.Incomplete, "pg-tf-exports") {
		t.Errorf("web plan: the bucket's policy is known only after apply: %q", r.Incomplete)
	}
	r = verdict(t, read("mod-create.json"))
	if got := routes(r); len(got) != 0 {
		t.Errorf("module plan: its instances are open on IPv6 only and have no IPv6 address: %v", got)
	}
}

// A new instance gets its public address from its subnet, or from an Elastic IP bound to
// it in the same plan. Neither, and the open group reaches nothing.
func TestANewInstanceIsAddressedTheWayAWSWillAddressIt(t *testing.T) {
	base := func(mapPublic bool) []res {
		return []res{
			{addr: "aws_route_table.main", values: map[string]any{"id": "rtb-0a1", "route": []any{map[string]any{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-0a1"}}}},
			{addr: "aws_route_table_association.web", values: map[string]any{"id": "a-1", "subnet_id": "subnet-0a1", "route_table_id": "rtb-0a1"}},
			{addr: "aws_subnet.web", values: map[string]any{"id": "subnet-0a1", "map_public_ip_on_launch": mapPublic}},
			{addr: "aws_security_group.web", values: map[string]any{"id": "sg-0a1", "name": "web", "ingress": []any{ingress(22, "0.0.0.0/0")}}},
			{addr: "aws_instance.db", values: map[string]any{"id": "i-0db", "subnet_id": "subnet-0db", "vpc_security_group_ids": []any{"sg-0db"},
				"private_ip": "10.0.9.9", "public_ip": "", "tags": map[string]any{"Name": "db", "crown-jewel": "true"}}},
			{addr: "aws_security_group.db", values: map[string]any{"id": "sg-0db", "name": "db", "ingress": []any{
				map[string]any{"from_port": 5432, "to_port": 5432, "protocol": "tcp", "cidr_blocks": []any{}, "ipv6_cidr_blocks": []any{},
					"security_groups": []any{"sg-0a1"}, "self": false}}}},
		}
	}
	instance := res{addr: "aws_instance.bastion", actions: []string{"create"},
		values:  map[string]any{"subnet_id": "subnet-0a1", "vpc_security_group_ids": []any{"sg-0a1"}, "tags": map[string]any{"Name": "bastion"}},
		unknown: map[string]any{"id": true, "public_ip": true, "private_ip": true, "associate_public_ip_address": true}}
	eip := res{addr: "aws_eip.bastion", actions: []string{"create"}, values: map[string]any{"domain": "vpc"},
		unknown: map[string]any{"id": true, "instance": true, "public_ip": true}, refs: map[string][]string{"instance": {"aws_instance.bastion.id", "aws_instance.bastion"}}}
	want := "introduced: bastion -> db"

	prior := base(true)
	r := verdict(t, planOf(t, prior, append(append([]res(nil), prior...), instance)))
	if got := routes(r); !has(got, want) {
		t.Errorf("a subnet that hands out public addresses: %v", got)
	}
	// The groups and routes it joins are the configuration's, unchanged.
	if r.Incomplete != "" {
		t.Errorf("incomplete = %q, want nothing outside the plan", r.Incomplete)
	}
	prior = base(false)
	if got := routes(verdict(t, planOf(t, prior, append(append([]res(nil), prior...), instance)))); len(got) != 0 {
		t.Errorf("a subnet that hands out none, and no Elastic IP: %v", got)
	}
	if got := routes(verdict(t, planOf(t, prior, append(append([]res(nil), prior...), instance, eip)))); !has(got, want) {
		t.Errorf("an Elastic IP bound to it: %v", got)
	}
	assoc := res{addr: "aws_eip_association.bastion", actions: []string{"create"}, values: map[string]any{"allocation_id": "eipalloc-0a1"},
		unknown: map[string]any{"id": true, "instance_id": true}, refs: map[string][]string{"instance_id": {"aws_instance.bastion.id", "aws_instance.bastion"}}}
	if got := routes(verdict(t, planOf(t, prior, append(append([]res(nil), prior...), instance, assoc)))); !has(got, want) {
		t.Errorf("an Elastic IP associated with it: %v", got)
	}
}

// A route table written with its routes as one expression: each route's target is the
// reference of the right type - the default route the internet gateway, the other the
// peering connection - not every reference the expression holds.
func TestEachRouteTakesTheTargetOfItsType(t *testing.T) {
	routeTable := res{addr: "aws_route_table.public", actions: []string{"create"},
		values: map[string]any{"route": []any{
			map[string]any{"cidr_block": "0.0.0.0/0", "nat_gateway_id": "", "vpc_peering_connection_id": ""},
			map[string]any{"cidr_block": "10.9.0.0/16", "gateway_id": "", "nat_gateway_id": ""},
		}},
		unknown: map[string]any{"id": true, "route": []any{map[string]any{"gateway_id": true}, map[string]any{"vpc_peering_connection_id": true}}},
		refs:    map[string][]string{"route": {"aws_internet_gateway.gw.id", "aws_internet_gateway.gw", "aws_vpc_peering_connection.partner.id", "aws_vpc_peering_connection.partner"}},
	}
	planned := []res{
		{addr: "aws_internet_gateway.gw", actions: []string{"create"}, values: map[string]any{}, unknown: map[string]any{"id": true}},
		{addr: "aws_vpc_peering_connection.partner", actions: []string{"create"}, values: map[string]any{}, unknown: map[string]any{"id": true}},
		routeTable,
		{addr: "aws_route_table_association.web", values: map[string]any{"id": "a-1", "subnet_id": "subnet-0a1"},
			unknown: map[string]any{"route_table_id": true}, actions: []string{"create"},
			refs: map[string][]string{"route_table_id": {"aws_route_table.public.id", "aws_route_table.public"}}},
		{addr: "aws_subnet.web", values: map[string]any{"id": "subnet-0a1", "map_public_ip_on_launch": true}},
		{addr: "aws_security_group.web", values: map[string]any{"id": "sg-0a1", "name": "web", "ingress": []any{ingress(22, "0.0.0.0/0")}}},
		{addr: "aws_instance.web", values: map[string]any{"id": "i-0a1", "subnet_id": "subnet-0a1", "vpc_security_group_ids": []any{"sg-0a1"},
			"iam_instance_profile": "web", "tags": map[string]any{"Name": "web-1"}},
			unknown: map[string]any{"public_ip": true, "private_ip": true}},
		{addr: "aws_iam_instance_profile.web", values: map[string]any{"name": "web", "role": "web"}},
		{addr: "aws_iam_role.web", values: map[string]any{"name": "web", "path": "/", "arn": "arn:aws:iam::" + account + ":role/web",
			"assume_role_policy": `{"Statement":[]}`}},
		{addr: "aws_iam_role_policy_attachment.admin", values: map[string]any{"role": "web", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
	}
	if got := routes(verdict(t, planOf(t, nil, planned))); !has(got, "introduced: web-1 -> web -> account-admin (effective)") {
		t.Errorf("routes = %v: the default route goes to the internet gateway", got)
	}
}

// verdictOn runs the plan against an estate, as the server and a live local run do.
func verdictOn(t *testing.T, plan string, estate graph.Snapshot) impact.Result {
	t.Helper()
	ch, err := terraform.New().ParseChange(strings.NewReader(plan),
		ingestion.Options{RepoSlug: "acme/infra", CommitSHA: "c0ffee", EstateKnown: true})
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

// An instance in a subnet the configuration does not describe: the plan cannot see its
// routing, and on its own judges it by its security groups - open, so exposed, erring
// toward reporting. The account knows better: the subnet has no route to an internet
// gateway. When the plan does not touch the instance's exposure, the estate's verdict
// stands, and a change behind it - an administrator policy on its role - opens nothing.
func TestTheEstateDecidesAnExposureThePlanDoesNotTouch(t *testing.T) {
	prior := []res{
		{addr: "aws_security_group.web", values: map[string]any{"id": "sg-0a1", "name": "web", "ingress": []any{ingress(22, "0.0.0.0/0")}}},
		{addr: "aws_iam_role.web", values: map[string]any{"name": "web", "path": "/", "arn": "arn:aws:iam::" + account + ":role/web",
			"assume_role_policy": `{"Statement":[]}`}},
		{addr: "aws_iam_instance_profile.web", values: map[string]any{"name": "web", "arn": "arn:aws:iam::" + account + ":instance-profile/web", "role": "web"}},
		{addr: "aws_instance.web", values: map[string]any{"id": "i-0a1", "subnet_id": "subnet-elsewhere", "vpc_security_group_ids": []any{"sg-0a1"},
			"iam_instance_profile": "web", "private_ip": "10.0.1.10", "public_ip": "203.0.113.10", "tags": map[string]any{"Name": "web-1"}}},
	}
	planned := append(append([]res(nil), prior...), res{addr: "aws_iam_role_policy_attachment.admin", actions: []string{"create"},
		values: map[string]any{"role": "web", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}})
	plan := planOf(t, prior, planned)

	// On its own the plan reports the route: an open group, and nothing said otherwise.
	if got := routes(verdict(t, plan)); !has(got, "introduced: web-1 -> web -> account-admin (effective)") {
		t.Errorf("plan alone: %v", got)
	}
	// Against the account, which read the instance as unreachable, it does not.
	vm := ontology.ScopedID(ontology.LabelVirtualMachine, account, "i-0a1")
	estate := graph.Snapshot{Nodes: []ontology.Node{{ID: vm, Label: ontology.LabelVirtualMachine, Name: "web-1",
		Properties: map[string]any{ontology.PropNetworkExposed: false, "net_reachability": "SG-open but in a private subnet (no internet-gateway route)"}}}}
	if got := routes(verdictOn(t, plan, estate)); len(got) != 0 {
		t.Errorf("against the estate: %v, want none - the account says the instance is unreachable", got)
	}

	// A plan that changes the instance's exposure is still judged on what it says.
	opened := changed(planned, "aws_security_group.web", map[string]any{"id": "sg-0a1", "name": "web",
		"ingress": []any{ingress(22, "0.0.0.0/0"), ingress(3389, "0.0.0.0/0")}})
	if got := routes(verdictOn(t, planOf(t, prior, opened), estate)); !has(got, "introduced: web-1 -> web -> account-admin (effective)") {
		t.Errorf("a plan that opens more ports: %v", got)
	}
}

// A function the configuration does not manage, which the plan only adds a permission to:
// its record holds only the plan's statement, so it can say the function is open, never
// that it is closed. The estate knows its URL answers anyone.
func TestAPartialRecordNeverClosesWhatTheEstateSaysIsOpen(t *testing.T) {
	fnARN := "arn:aws:lambda:eu-north-1:" + account + ":function:orders-api"
	role := res{addr: "aws_iam_role.fn", values: map[string]any{"name": "fn", "path": "/", "arn": "arn:aws:iam::" + account + ":role/fn",
		"assume_role_policy": `{"Statement":[]}`}}
	prior := []res{role}
	planned := []res{role,
		{addr: "aws_lambda_permission.events", actions: []string{"create"}, values: map[string]any{"function_name": "orders-api",
			"principal": "events.amazonaws.com", "action": "lambda:InvokeFunction", "statement_id": "events"}},
		{addr: "aws_iam_role_policy_attachment.admin", actions: []string{"create"},
			values: map[string]any{"role": "fn", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
	}
	fn := ontology.NewID(ontology.LabelFunction, fnARN)
	roleID := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::"+account+":role/fn")
	estate := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: fn, Label: ontology.LabelFunction, Name: "orders-api", Properties: map[string]any{ontology.PropNetworkExposed: true,
				ontology.PropInternetExposed: true, "exposure": "function URL without authentication"}},
			{ID: roleID, Label: ontology.LabelIAMRole, Name: "fn", Properties: map[string]any{ontology.PropARN: "arn:aws:iam::" + account + ":role/fn"}},
		},
		Edges: []ontology.Edge{{Type: ontology.EdgeAssumes, From: fn, To: roleID, ExploitProbability: 0.9}},
	}
	if got := routes(verdictOn(t, planOf(t, prior, planned), estate)); !has(got, "introduced: orders-api -> fn -> account-admin (effective)") {
		t.Errorf("routes = %v: the function stays open, as the estate says", got)
	}
}

// A list partly known - a group named by its id beside one the plan creates - keeps the
// one it has and gains the other.
func TestAPartlyKnownListKeepsWhatItHas(t *testing.T) {
	sg := res{addr: "aws_security_group.new", actions: []string{"create"}, values: map[string]any{"name": "new", "ingress": []any{ingress(22, "0.0.0.0/0")}},
		unknown: map[string]any{"id": true}}
	inst := res{addr: "aws_instance.web", values: map[string]any{"id": "i-0a1", "vpc_security_group_ids": []any{nil, "sg-existing"},
		"private_ip": "10.0.1.10", "public_ip": "203.0.113.10", "tags": map[string]any{"Name": "web-1"}},
		unknown: map[string]any{"vpc_security_group_ids": []any{true, false}}, actions: []string{"update"},
		refs: map[string][]string{"vpc_security_group_ids": {"aws_security_group.new.id", "aws_security_group.new"}}}
	ch, err := terraform.New().ParseChange(strings.NewReader(planOf(t, nil, []res{sg, inst})), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var exposed bool
	for _, ev := range ch.After {
		for _, n := range ev.Nodes {
			if n.Name == "web-1" {
				exposed, _ = n.Properties[ontology.PropNetworkExposed].(bool)
			}
		}
	}
	if !exposed {
		t.Error("web-1 joins the new group, which is open: the known group must not hide it, nor it the known one")
	}
}

// A subnet with no route table of its own uses its VPC's main one. A VPC the plan creates
// gets AWS's, which routes only inside it: the instance with a public address and an open
// group in it is reached by nothing. The same plan adopting that main table and giving it
// a route to the internet gateway opens the instance, and the policy attached to its role
// - through aws_iam_policy_attachment, which names roles by the list - makes it a route to
// account administrator. Both are real plans.
func TestTheMainRouteTableDecidesAnUnassociatedSubnet(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := routes(verdict(t, read("mainrt-private.json"))); len(got) != 0 {
		t.Errorf("a new VPC's own main table routes nowhere: %v", got)
	}
	if got := routes(verdict(t, read("mainrt-igw.json"))); !has(got, "introduced: app-1 -> app -> account-admin (effective)") {
		t.Errorf("the adopted main table routes to the internet gateway: %v", got)
	}
}
