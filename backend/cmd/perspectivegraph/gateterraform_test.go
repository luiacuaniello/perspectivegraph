package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const planFixture = "../../internal/ingestion/terraform/testdata/web-create.json"

// A Terraform plan is judged on its own in local mode: it carries the state it starts
// from, so no -estate or -aws-region is needed to answer whether it opens a route.
func TestLocalModeJudgesAPlanOnItsOwn(t *testing.T) {
	o := localOpts{slug: localSlug, sha: localSHA, repository: localSlug, attribution: "diff",
		reports: []reportSpec{{source: "terraform", path: planFixture}}}
	v, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, p := range v.Paths {
		var names []string
		for _, n := range p.Nodes {
			names = append(names, n.Name)
		}
		routes = append(routes, strings.Join(names, " -> "))
	}
	want := "web-1 -> web-role -> account-admin (effective)"
	found := false
	for _, r := range routes {
		found = found || r == want
	}
	if !found || !v.Analysed {
		t.Errorf("routes = %v, analysed = %v: want %q", routes, v.Analysed, want)
	}
	// The plan names a bucket policy it builds from the bucket's own ARN: the routes found
	// stand, and the verdict says what could not be judged.
	if !strings.Contains(v.Incomplete, "pg-tf-exports") {
		t.Errorf("incomplete = %q", v.Incomplete)
	}
}

// A plan describes what is not deployed: the gate reads it, the ingest webhook does not,
// and -persist, which would write it into the live graph, is refused.
func TestAPlanIsTheGatesAlone(t *testing.T) {
	if _, ok := collectorFor("terraform"); !ok {
		t.Error("the gate must read terraform plans")
	}
	for _, c := range ingestCollectors() {
		if _, change := c.(ingestion.ChangeParser); change {
			t.Errorf("the ingest webhook must not take %s reports", c.Source())
		}
	}
	err := runGate([]string{"-source", "terraform", "-report", planFixture, "-persist", "-slug", "acme/infra", "-sha", "c0ffee"})
	if err == nil || !strings.Contains(err.Error(), "never written into the live graph") {
		t.Errorf("-persist with a plan: err = %v", err)
	}
}

// A plan read against a live estate leaves to the estate what it cannot judge better. The
// instance below sits in a subnet the configuration does not describe; the plan alone
// judges it by its open group, and the account says it is unreachable. The plan only
// attaches a policy to its role, so the account's verdict stands - and the account the
// estate was read from keys the plan's instance, which names none of its own.
func TestLocalModeLetsTheLiveEstateDecideWhatThePlanCannot(t *testing.T) {
	const acct = "111122223333"
	plan := `{
	 "format_version": "1.2",
	 "prior_state": {"values": {"root_module": {"resources": [
	  {"address": "aws_security_group.web", "mode": "managed", "type": "aws_security_group", "name": "web",
	   "values": {"id": "sg-0a1", "name": "web", "ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}},
	  {"address": "aws_iam_role.web", "mode": "managed", "type": "aws_iam_role", "name": "web",
	   "values": {"name": "web", "path": "/", "assume_role_policy": "{\"Statement\":[]}"}},
	  {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
	   "values": {"id": "i-0a1", "subnet_id": "subnet-elsewhere", "vpc_security_group_ids": ["sg-0a1"], "iam_instance_profile": "web",
	    "private_ip": "10.0.1.10", "public_ip": "203.0.113.10", "tags": {"Name": "web-1"}}},
	  {"address": "aws_iam_instance_profile.web", "mode": "managed", "type": "aws_iam_instance_profile", "name": "web",
	   "values": {"name": "web", "role": "web"}}
	 ]}}},
	 "planned_values": {"root_module": {"resources": [
	  {"address": "aws_security_group.web", "mode": "managed", "type": "aws_security_group", "name": "web",
	   "values": {"id": "sg-0a1", "name": "web", "ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}},
	  {"address": "aws_iam_role.web", "mode": "managed", "type": "aws_iam_role", "name": "web",
	   "values": {"name": "web", "path": "/", "assume_role_policy": "{\"Statement\":[]}"}},
	  {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
	   "values": {"id": "i-0a1", "subnet_id": "subnet-elsewhere", "vpc_security_group_ids": ["sg-0a1"], "iam_instance_profile": "web",
	    "private_ip": "10.0.1.10", "public_ip": "203.0.113.10", "tags": {"Name": "web-1"}}},
	  {"address": "aws_iam_instance_profile.web", "mode": "managed", "type": "aws_iam_instance_profile", "name": "web",
	   "values": {"name": "web", "role": "web"}},
	  {"address": "aws_iam_role_policy_attachment.admin", "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": "admin",
	   "values": {"role": "web", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}}
	 ]}},
	 "resource_changes": [{"address": "aws_iam_role_policy_attachment.admin", "change": {"actions": ["create"], "after_unknown": {"id": true}}}],
	 "configuration": {"root_module": {"resources": []}}
	}`
	path := t.TempDir() + "/plan.json"
	if err := os.WriteFile(path, []byte(plan), 0o600); err != nil {
		t.Fatal(err)
	}
	o := localOpts{slug: localSlug, sha: localSHA, repository: localSlug, attribution: "diff",
		reports: []reportSpec{{source: "terraform", path: path}}}

	alone, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if alone.CriticalPaths == 0 {
		t.Fatal("the plan alone judges web-1 by its open group, and reports the route")
	}

	o.collectAWSFn = func(context.Context) ([]ontology.Event, error) {
		return []ontology.Event{{Source: "cloudnet", Kind: ontology.KindRelationship, Nodes: []ontology.Node{{
			ID: ontology.ScopedID(ontology.LabelVirtualMachine, acct, "i-0a1"), Label: ontology.LabelVirtualMachine, Name: "web-1",
			Properties: map[string]any{ontology.PropAccount: acct, ontology.PropNetworkExposed: false,
				"net_reachability": "SG-open but in a private subnet (no internet-gateway route)"},
		}}}}, nil
	}
	live, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if live.CriticalPaths != 0 {
		t.Errorf("against the live account: %d path(s), want none - it says web-1 is unreachable", live.CriticalPaths)
	}

	// And when the account says web-1 is reachable, the plan's instance is that instance -
	// keyed with the estate's account - so the policy the plan attaches opens the route.
	o.collectAWSFn = func(context.Context) ([]ontology.Event, error) {
		return []ontology.Event{{Source: "cloudnet", Kind: ontology.KindRelationship, Nodes: []ontology.Node{{
			ID: ontology.ScopedID(ontology.LabelVirtualMachine, acct, "i-0a1"), Label: ontology.LabelVirtualMachine, Name: "web-1",
			Properties: map[string]any{ontology.PropAccount: acct, ontology.PropNetworkExposed: true, ontology.PropInternetExposed: true},
		}}}}, nil
	}
	open, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if open.CriticalPaths == 0 {
		t.Error("the account says web-1 is reachable: the plan's administrator policy opens the route")
	}
}
