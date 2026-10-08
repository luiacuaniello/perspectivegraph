package terraform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
)

func readFixture(t *testing.T, name string) *Plan {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := Read(f, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The fixtures are real: `terraform show -json` of plans made with the AWS provider,
// offline, so every attribute AWS assigns on apply is unknown in them - the case a pull
// request that adds infrastructure always is.

// An identifier known only after apply is what the configuration builds it from: an
// instance's subnet and group, created by the same plan, are those resources' placeholders,
// with the prefix AWS will give them; a route's internet gateway likewise, through a block
// the configuration writes as one expression.
func TestUnknownIdentifiersFollowTheConfiguration(t *testing.T) {
	p := readFixture(t, "web-create.json")
	web := p.byAddr[Planned]["aws_instance.web"]
	if got := p.Str(Planned, web, "subnet_id"); got != "subnet-planned:aws_subnet.public" {
		t.Errorf("subnet_id = %q", got)
	}
	if got := p.Strs(Planned, web, "vpc_security_group_ids"); len(got) != 1 || got[0] != "sg-planned:aws_security_group.web" {
		t.Errorf("vpc_security_group_ids = %v", got)
	}
	rt := p.byAddr[Planned]["aws_route_table.public"]
	if got := p.routeOf(Planned, rt, "route", 0).GatewayID; got != "igw-planned:aws_internet_gateway.gw" {
		t.Errorf("route gateway = %q, want the internet gateway's placeholder: a route to igw-… is what makes a subnet public", got)
	}
	// An IAM role's ARN is built from its name, as AWS builds it.
	role := p.byAddr[Planned]["aws_iam_role.web"]
	if got := p.arnOf(Planned, role); got != "arn:aws:iam::planned:role/web-role" {
		t.Errorf("role ARN = %q", got)
	}
}

// A document built from a resource not created yet - a bucket policy naming the bucket's
// own ARN - is unknown, and stays unknown: its references are what it is built FROM, not
// what it is, and reading the bucket's ARN as the policy would invent a document.
func TestADocumentIsNeverTakenForWhatItReferences(t *testing.T) {
	p := readFixture(t, "web-create.json")
	pol := p.byAddr[Planned]["aws_s3_bucket_policy.exports"]
	if got := p.Str(Planned, pol, "policy"); got != "" {
		t.Errorf("policy = %q, want unknown", got)
	}
	if p.Known(Planned, pol, "policy") {
		t.Error("the policy must read as unknown")
	}
	if got := p.Str(Planned, pol, "bucket"); got != "pg-tf-exports" {
		t.Errorf("bucket = %q: an identifier attribute does follow its reference", got)
	}
	_, notes := p.s3(Planned)
	if len(notes) != 1 || !strings.Contains(notes[0], "pg-tf-exports") {
		t.Errorf("notes = %v, want the bucket's policy noted as known only after apply", notes)
	}
}

// Through a module: an input variable resolves in the calling module, an output in the
// called one, and a for_each instance keeps its key.
func TestReferencesCrossModules(t *testing.T) {
	p := readFixture(t, "mod-create.json")
	a := p.byAddr[Planned][`module.app.aws_instance.this["a"]`]
	if a == nil {
		t.Fatal("the for_each instance is missing")
	}
	if got := p.Str(Planned, a, "subnet_id"); got != "subnet-planned:aws_subnet.a" {
		t.Errorf("subnet through var.subnet_id = %q", got)
	}
	if got := p.Strs(Planned, a, "vpc_security_group_ids"); len(got) != 1 || got[0] != "sg-planned:module.app.aws_security_group.this" {
		t.Errorf("group inside the module = %v", got)
	}
	rule := p.byAddr[Planned]["aws_security_group_rule.from_app"]
	if got := p.Str(Planned, rule, "source_security_group_id"); got != "sg-planned:module.app.aws_security_group.this" {
		t.Errorf("group through module.app.sg_id = %q", got)
	}
	if got := p.Str(Planned, rule, "security_group_id"); got != "sg-planned:aws_vpc.main.default" {
		t.Errorf("the VPC's default group = %q", got)
	}
	prof := p.byAddr[Planned]["module.app.aws_iam_instance_profile.this"]
	if got := p.roleARN(Planned, p.Str(Planned, prof, "role")); got != "arn:aws:iam::planned:role/team/app-role" {
		t.Errorf("profile role = %q, want the role's ARN with its path", got)
	}
}

// An instance's public address: asked for, bound by an Elastic IP, or handed out by its
// subnet. When none of that can be told, none is recorded and the security groups alone
// decide - erring toward reporting.
func TestPlannedAddresses(t *testing.T) {
	p := readFixture(t, "web-create.json")
	b, _ := p.network(Planned)
	got := map[string]instRecord{}
	for _, i := range b.Instances {
		got[i.InstanceID] = i
	}
	if web := got["i-planned:aws_instance.web"]; web.PublicIPAddress == "" || web.PrivateIPAddress == "" {
		t.Errorf("web has an Elastic IP and a public subnet: %+v", web)
	}
	if db := got["i-planned:aws_instance.db[0]"]; db.PublicIPAddress != "" || db.PrivateIPAddress == "" {
		t.Errorf("db sits in a subnet that hands out no public address: %+v", db)
	}
	m := readFixture(t, "mod-create.json")
	mb, _ := m.network(Planned)
	for _, i := range mb.Instances {
		if i.PublicIPAddress == "" {
			t.Errorf("%s asks for a public address: %+v", i.InstanceID, i)
		}
	}
}

func TestAccountAndRegionFromThePlan(t *testing.T) {
	p := readFixture(t, "web-create.json")
	if p.Region != "eu-north-1" {
		t.Errorf("region = %q, from the provider block", p.Region)
	}
	if p.Account != "" {
		t.Errorf("account = %q: a plan of new resources names none", p.Account)
	}
	f, _ := os.Open("testdata/web-create.json")
	defer f.Close()
	q, err := Read(f, "111122223333", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := q.arnOf(Planned, q.byAddr[Planned]["aws_iam_role.web"]); got != "arn:aws:iam::111122223333:role/web-role" {
		t.Errorf("with the account given, role ARN = %q", got)
	}
}

func TestNotAPlan(t *testing.T) {
	if _, err := Read(strings.NewReader(`{"format_version":"1.0","values":{}}`), "", ""); err == nil {
		t.Error("a state file, not a plan, must be refused")
	}
	if _, err := Read(strings.NewReader(`{`), "", ""); err == nil {
		t.Error("broken JSON must be refused")
	}
}

// A plan is input, and the pull request's author writes the configuration behind it. One
// written by hand can make two attributes refer to each other; following that has to stop
// rather than recurse until the process dies.
func TestReferencesThatLoopBackEnd(t *testing.T) {
	plan := `{
	 "planned_values": {"root_module": {"resources": [
	  {"address": "aws_instance.a", "mode": "managed", "type": "aws_instance", "name": "a", "values": {}},
	  {"address": "aws_subnet.b", "mode": "managed", "type": "aws_subnet", "name": "b", "values": {}}
	 ]}},
	 "resource_changes": [
	  {"address": "aws_instance.a", "change": {"actions": ["create"], "after_unknown": {"subnet_id": true, "id": true}}},
	  {"address": "aws_subnet.b", "change": {"actions": ["create"], "after_unknown": {"id": true}}}
	 ],
	 "configuration": {"root_module": {"resources": [
	  {"address": "aws_instance.a", "mode": "managed", "type": "aws_instance", "name": "a",
	   "expressions": {"subnet_id": {"references": ["aws_subnet.b.id"]}}},
	  {"address": "aws_subnet.b", "mode": "managed", "type": "aws_subnet", "name": "b",
	   "expressions": {"id": {"references": ["aws_instance.a.subnet_id"]}}}
	 ]}}
	}`
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := New().ParseChange(strings.NewReader(plan), ingestion.Options{}); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("following references that loop back never ended")
	}
}

// A plan's size is its author's to choose, up to the gate's 32 MiB. Reading it has to grow
// with its size, not with the square of it: looking up each instance profile's role among
// all the roles, and each instance's groups among all the groups, once took 3.8 s for a 7 MiB
// plan and would have taken a minute and a half at the limit. The bound is loose - a tenth
// of it is what the reader needs - so only the square trips it.
func TestReadingAPlanGrowsWithItsSize(t *testing.T) {
	var res []any
	add := func(typ, name string, v map[string]any) {
		res = append(res, map[string]any{"address": typ + "." + name, "mode": "managed", "type": typ, "name": name, "values": v})
	}
	const n = 3000
	for i := 0; i < n; i++ {
		s := fmt.Sprint(i)
		add("aws_security_group", "g"+s, map[string]any{"id": "sg-" + s, "name": "g" + s, "ingress": []any{}})
		add("aws_security_group_rule", "r"+s, map[string]any{"type": "ingress", "security_group_id": "sg-" + s, "from_port": 22, "to_port": 22,
			"protocol": "tcp", "source_security_group_id": fmt.Sprint("sg-", (i+1)%n)})
		add("aws_subnet", "s"+s, map[string]any{"id": "subnet-" + s})
		add("aws_route_table_association", "a"+s, map[string]any{"subnet_id": "subnet-" + s, "route_table_id": "rtb-" + s})
		add("aws_route_table", "t"+s, map[string]any{"id": "rtb-" + s, "route": []any{}})
		add("aws_iam_role", "role"+s, map[string]any{"name": "role" + s, "path": "/", "assume_role_policy": `{"Statement":[]}`})
		add("aws_iam_instance_profile", "p"+s, map[string]any{"name": "p" + s, "role": "role" + s})
		add("aws_iam_role_policy", "rp"+s, map[string]any{"name": "rp" + s, "role": "role" + s,
			"policy": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`})
		add("aws_instance", "i"+s, map[string]any{"id": "i-" + s, "subnet_id": "subnet-" + s, "vpc_security_group_ids": []any{"sg-" + s},
			"iam_instance_profile": "p" + s, "private_ip": "10.0.0.1", "public_ip": ""})
		// Everything a hostile plan could pile onto one load balancer, one API, one ACL and
		// one cluster.
		add("aws_lb_target_group", "tg"+s, map[string]any{"arn": "arn:aws:elasticloadbalancing:eu-north-1:111122223333:targetgroup/tg" + s + "/x", "name": "tg" + s})
		add("aws_lb_listener", "l"+s, map[string]any{"load_balancer_arn": "arn:aws:elasticloadbalancing:eu-north-1:111122223333:loadbalancer/app/edge/x",
			"port": 80, "default_action": []any{map[string]any{"type": "forward",
				"target_group_arn": "arn:aws:elasticloadbalancing:eu-north-1:111122223333:targetgroup/tg" + s + "/x"}}})
		add("aws_api_gateway_method", "m"+s, map[string]any{"rest_api_id": "api0", "resource_id": "r" + s, "http_method": "GET", "authorization": "NONE"})
		add("aws_api_gateway_stage", "st"+s, map[string]any{"rest_api_id": "api0", "stage_name": "s" + s})
		add("aws_network_acl_rule", "acl"+s, map[string]any{"network_acl_id": "acl-0", "rule_number": i, "protocol": "tcp",
			"rule_action": "allow", "cidr_block": "0.0.0.0/0", "from_port": 22, "to_port": 22})
		add("aws_eks_access_policy_association", "e"+s, map[string]any{"cluster_name": "prod",
			"principal_arn": "arn:aws:iam::111122223333:role/role" + s, "policy_arn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"})
	}
	values := map[string]any{"root_module": map[string]any{"resources": res}}
	raw, err := json.Marshal(map[string]any{"format_version": "1.2", "planned_values": values,
		"prior_state": map[string]any{"values": values}, "configuration": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := New().ParseChange(bytes.NewReader(raw), ingestion.Options{EstateKnown: true}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("a %d KiB plan took %v to read", len(raw)/1024, took)
	}
}
