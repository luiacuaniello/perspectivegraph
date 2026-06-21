package iam

import (
	"os"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestBuildsPrivescGraph(t *testing.T) {
	f, err := os.Open("../../../testdata/iam-sample.json")
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
	escalatesTo := func(from, to string) bool {
		for _, e := range ev.Edges {
			if e.Type == ontology.EdgeCanEscalateTo && e.From == from && e.To == to {
				return true
			}
		}
		return false
	}
	has := func(et ontology.EdgeType, from, to string) bool {
		for _, e := range ev.Edges {
			if e.Type == et && e.From == from && e.To == to {
				return true
			}
		}
		return false
	}

	adminID := ontology.NewID(ontology.LabelIAMRole, "perspectivegraph:account-admin")
	publicDeployer := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::123456789012:role/public-deployer")
	adminRole := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::123456789012:role/admin-role")
	appReadonly := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::123456789012:role/app-readonly")
	ciBot := ontology.NewID(ontology.LabelUser, "arn:aws:iam::123456789012:user/ci-bot")

	// The crown jewel exists and is marked as such.
	if j, ok := byID[adminID]; !ok || !j.Bool(ontology.PropCrownJewel) {
		t.Fatalf("account-admin should be a crown jewel: %+v", j)
	}

	// A role anyone can assume is internet-reachable — the seed of a full path.
	if r, ok := byID[publicDeployer]; !ok || !r.Bool(ontology.PropInternetExposed) {
		t.Errorf("public-deployer (trust *) should be internet_exposed: %+v", r)
	}

	// The self-contained critical path: public-deployer (PassRole+Lambda) → admin.
	if !escalatesTo(publicDeployer, adminID) {
		t.Error("missing public-deployer --CAN_ESCALATE_TO--> account-admin")
	}
	// A user with iam:AttachUserPolicy can escalate.
	if !escalatesTo(ciBot, adminID) {
		t.Error("missing ci-bot --CAN_ESCALATE_TO--> account-admin")
	}
	// An already-admin role still points at the crown jewel.
	if !escalatesTo(adminRole, adminID) {
		t.Error("missing admin-role --CAN_ESCALATE_TO--> account-admin")
	}
	// Role chaining: ci-bot is trusted to assume admin-role.
	if !has(ontology.EdgeAssumes, ciBot, adminRole) {
		t.Error("missing ci-bot --ASSUMES--> admin-role (trust policy)")
	}

	// Precision: a read-only role must NOT be flagged as able to escalate.
	if escalatesTo(appReadonly, adminID) {
		t.Error("app-readonly is benign and must not escalate (false positive)")
	}
}

func TestMatchActionWildcards(t *testing.T) {
	cases := []struct {
		pattern, action string
		want            bool
	}{
		{"*", "iam:AttachRolePolicy", true},
		{"iam:*", "iam:AttachRolePolicy", true},
		{"iam:Attach*", "iam:AttachRolePolicy", true},
		{"iam:Attach*", "iam:PutRolePolicy", false},
		{"iam:AttachRolePolicy", "iam:attachrolepolicy", true}, // case-insensitive
		{"s3:*", "iam:PassRole", false},
		{"*RolePolicy", "iam:AttachRolePolicy", true},
		{"iam:Put?olicy", "iam:PutPolicy", false}, // '?' treated literally, no match
	}
	for _, c := range cases {
		if got := matchAction(c.pattern, c.action); got != c.want {
			t.Errorf("matchAction(%q, %q) = %v, want %v", c.pattern, c.action, got, c.want)
		}
	}
}

func TestDetectPrivescPassRoleNeedsCompute(t *testing.T) {
	// iam:PassRole alone is not escalation; pairing it with a compute action is.
	passOnly := actionSet{}.add("iam:PassRole")
	if got := detectPrivesc(passOnly); len(got) != 0 {
		t.Errorf("iam:PassRole alone should not escalate, got %v", got)
	}
	passLambda := actionSet{}.add("iam:PassRole").add("lambda:CreateFunction")
	if got := detectPrivesc(passLambda); len(got) == 0 {
		t.Error("iam:PassRole + lambda:CreateFunction should be detected")
	}
}
