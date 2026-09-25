package custodian

import (
	"os"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestParseCloudScenario(t *testing.T) {
	f, err := os.Open("../../../testdata/custodian-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	events, err := New().Parse(f, ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]

	byLabel := map[ontology.Label]ontology.Node{}
	for _, n := range ev.Nodes {
		byLabel[n.Label] = n
	}

	vm, ok := byLabel[ontology.LabelVirtualMachine]
	if !ok || !vm.Bool(ontology.PropInternetExposed) {
		t.Errorf("EC2 should be an internet-exposed VirtualMachine: %+v", vm)
	}
	if vm.Name != "web-frontend" {
		t.Errorf("VM name = %q, want web-frontend (from Name tag)", vm.Name)
	}
	role, ok := byLabel[ontology.LabelIAMRole]
	if !ok || !role.Bool(ontology.PropCrownJewel) {
		t.Errorf("admin role should be a crown jewel: %+v", role)
	}
	bucket, ok := byLabel[ontology.LabelBucket]
	if !ok || !bucket.Bool(ontology.PropCrownJewel) {
		t.Errorf("sensitive bucket should be a crown jewel: %+v", bucket)
	}

	// Relationship edges: LB -ROUTES_TO-> VM -ASSUMES-> role -HAS_PERMISSION-> bucket.
	want := map[ontology.EdgeType]bool{
		ontology.EdgeRoutesTo:      false,
		ontology.EdgeAssumes:       false,
		ontology.EdgeHasPermission: false,
	}
	for _, e := range ev.Edges {
		if _, tracked := want[e.Type]; tracked {
			want[e.Type] = true
		}
	}
	for et, seen := range want {
		if !seen {
			t.Errorf("missing %s edge", et)
		}
	}
}

// A grant to everyone makes a bucket reachable; one that lets everyone READ makes it
// open - a crown jewel held by anyone, compromised as it stands. The two must not be
// confused: a write-only grant is exposure, not disclosure. AuthenticatedUsers is any
// AWS account in the world, not the owner's, and counts as everyone.
func TestPublicGrantTellsReachableFromOpen(t *testing.T) {
	acl := func(uri, perm string) map[string]any {
		return map[string]any{"Acl": map[string]any{"Grants": []any{
			map[string]any{"Grantee": map[string]any{"URI": uri}, "Permission": perm},
		}}}
	}
	const all, authed = "http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
	cases := []struct {
		name              string
		bucket            map[string]any
		granted, readable bool
	}{
		{"public read", acl(all, "READ"), true, true},
		{"public full control", acl(all, "FULL_CONTROL"), true, true},
		{"any AWS account may read", acl(authed, "READ"), true, true},
		{"public write only", acl(all, "WRITE"), true, false},
		{"owner only", acl("", "FULL_CONTROL"), false, false},
		{"no ACL", map[string]any{}, false, false},
	}
	for _, c := range cases {
		granted, readable := publicGrant(c.bucket)
		if granted != c.granted || readable != c.readable {
			t.Errorf("%s: granted=%v readable=%v, want %v %v", c.name, granted, readable, c.granted, c.readable)
		}
		b := &builder{nodes: map[string]ontology.Node{}, appOf: map[string]string{}}
		c.bucket["Name"] = "exports"
		b.bucket(c.bucket)
		n := b.nodes[ontology.NewID(ontology.LabelBucket, "exports")]
		if n.Bool(ontology.PropInternetExposed) != c.granted || n.Bool(ontology.PropPublicAccess) != c.readable {
			t.Errorf("%s: node exposed=%v public=%v, want %v %v", c.name,
				n.Bool(ontology.PropInternetExposed), n.Bool(ontology.PropPublicAccess), c.granted, c.readable)
		}
	}
}
