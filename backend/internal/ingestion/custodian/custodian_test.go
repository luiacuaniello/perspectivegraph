package custodian

import (
	"fmt"
	"os"
	"strings"
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

func parseBundle(t *testing.T, body string) ontology.Event {
	t.Helper()
	events, err := New().Parse(strings.NewReader(body), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return events[0]
}

func assumes(ev ontology.Event, from string) []ontology.Edge {
	var out []ontology.Edge
	for _, e := range ev.Edges {
		if e.Type == ontology.EdgeAssumes && e.From == from {
			out = append(out, e)
		}
	}
	return out
}

const account = "123456789012"

// The profile's name was read as the role's. A profile Terraform or CloudFormation creates
// is often named differently from its role, and the instance then reached a role nobody had
// defined: the admin role behind it, and every route through it, disappeared.
func TestAnInstanceAssumesTheRoleItsProfileCarries(t *testing.T) {
	ev := parseBundle(t, `{"account_id":"`+account+`","policies":[
	 {"resource":"aws.ec2","resources":[{"InstanceId":"i-1","IamInstanceProfile":{"Arn":"arn:aws:iam::`+account+`:instance-profile/web-profile"}}]},
	 {"resource":"aws.iam-profile","resources":[{"InstanceProfileName":"web-profile","Arn":"arn:aws:iam::`+account+`:instance-profile/web-profile",
	   "Roles":[{"RoleName":"web-role","Arn":"arn:aws:iam::`+account+`:role/web-role"}]}]},
	 {"resource":"aws.iam-role","resources":[{"RoleName":"web-role","Arn":"arn:aws:iam::`+account+`:role/web-role"}]}]}`)
	edges := assumes(ev, ontology.ScopedID(ontology.LabelVirtualMachine, account, "i-1"))
	want := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::"+account+":role/web-role")
	if len(edges) != 1 || edges[0].To != want {
		t.Fatalf("instance assumes %+v, want web-role by its ARN", edges)
	}
	if edges[0].ExploitProbability != ingestion.IMDSAssumeProb("") || edges[0].Properties[ontology.PropResolutionMethod] != nil {
		t.Errorf("a join the export states is not a guess: %+v", edges[0])
	}
}

// Without the profile in the export, the role is guessed to share its name - the console's
// default, often not infrastructure-as-code's - and the join says it is a guess.
func TestAProfileWithoutItsRoleIsAnInferredJoin(t *testing.T) {
	ev := parseBundle(t, `{"account_id":"`+account+`","policies":[
	 {"resource":"aws.ec2","resources":[{"InstanceId":"i-1","IamInstanceProfile":{"Arn":"arn:aws:iam::`+account+`:instance-profile/app"}}]}]}`)
	edges := assumes(ev, ontology.ScopedID(ontology.LabelVirtualMachine, account, "i-1"))
	if len(edges) != 1 {
		t.Fatalf("instance assumes %+v, want one guessed role", edges)
	}
	e := edges[0]
	if e.To != ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::"+account+":role/app") {
		t.Errorf("guessed role id = %s, want the ARN of a role named like the profile", e.To)
	}
	if e.Properties[ontology.PropResolutionMethod] != "instance-profile-name" || e.ExploitProbability >= ingestion.IMDSAssumeProb("") {
		t.Errorf("the guess must be marked and weigh less than a stated join: %+v", e)
	}
}

// The step from an instance to its role is scored from the instance's IMDS setting, as
// the network source scores the same step. Custodian used a flat 0.8, so once the two
// sources met on one edge its probability depended on which of them was written last:
// 0.6 or 0.8 for an instance that requires IMDSv2.
func TestTheInstanceRoleStepFollowsIMDS(t *testing.T) {
	for tokens, want := range map[string]float64{"required": 0.6, "optional": 0.9} {
		ev := parseBundle(t, `{"account_id":"`+account+`","policies":[
		 {"resource":"aws.ec2","resources":[{"InstanceId":"i-1","MetadataOptions":{"HttpTokens":"`+tokens+`"},
		   "IamInstanceProfile":{"Arn":"arn:aws:iam::`+account+`:instance-profile/app"}}]},
		 {"resource":"aws.iam-profile","resources":[{"InstanceProfileName":"app","Arn":"arn:aws:iam::`+account+`:instance-profile/app",
		   "Roles":[{"RoleName":"app","Arn":"arn:aws:iam::`+account+`:role/app"}]}]}]}`)
		edges := assumes(ev, ontology.ScopedID(ontology.LabelVirtualMachine, account, "i-1"))
		if len(edges) != 1 || edges[0].ExploitProbability != want {
			t.Errorf("HttpTokens=%s: instance assumes %+v, want p=%.1f", tokens, edges, want)
		}
	}
}

// Roles are keyed on their ARN and instances on their account, as the iam, cloudnet and
// SSO collectors key them - and never on a bare name a Kubernetes ClusterRole could have.
func TestIdentitiesAreKeyedLikeTheOtherAWSSources(t *testing.T) {
	ev := parseBundle(t, `{"account_id":"`+account+`","policies":[
	 {"resource":"aws.ec2","resources":[{"InstanceId":"i-1"}]},
	 {"resource":"aws.iam-role","resources":[{"RoleName":"admin","Arn":"arn:aws:iam::`+account+`:role/admin"},{"RoleName":"no-arn"}]}]}`)
	ids := map[string]bool{}
	for _, n := range ev.Nodes {
		ids[n.ID] = true
	}
	for name, id := range map[string]string{
		"instance, scoped to the account":                   ontology.ScopedID(ontology.LabelVirtualMachine, account, "i-1"),
		"role, by its ARN":                                  ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::"+account+":role/admin"),
		"role without an Arn, by the one AWS would give it": ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::"+account+":role/no-arn"),
	} {
		if !ids[id] {
			t.Errorf("missing the %s", name)
		}
	}
	if ids[ontology.NewID(ontology.LabelIAMRole, "admin")] {
		t.Error("a role keyed on its bare name merges with the Kubernetes ClusterRole of that name")
	}
}

// A load balancer routes only inside its Region; a Local Zone belongs to its parent, and
// an unknown Region matches anything, as it did before Regions were read.
func TestSameRegion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"eu-west-1", "eu-west-1", true}, {"eu-west-1", "us-east-1", false},
		{"us-west-2", "us-west-2-lax-1", true}, {"", "us-east-1", true}, {"us-east-1", "us-east-1-wl1-bos-wlz-1", true},
		{"us-east-1", "us-east-2", false},
	} {
		if got := sameRegion(c.a, c.b); got != c.want {
			t.Errorf("sameRegion(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A bucket is public through its policy as much as through its ACL - and since ACLs are
// off by default on new buckets, mostly through its policy. Block Public Access closes
// either, and the roles a policy names reach the data whatever their own policies say.
func TestBucketPolicyDecidesWhoReachesTheData(t *testing.T) {
	const public = `"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::b/*\"}]}"`
	const crossAccount = `"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::222222222222:role/analytics\"},\"Action\":[\"s3:GetObject\",\"s3:ListBucket\"],\"Resource\":\"*\"}]}"`
	ev := parseBundle(t, `{"account_id":"`+account+`","policies":[{"resource":"aws.s3","resources":[
	  {"Name":"open-by-policy","Policy":`+public+`,"Tags":[{"Key":"classification","Value":"pii"}]},
	  {"Name":"blocked","Policy":`+public+`,"c7n:PublicAccessBlock":{"RestrictPublicBuckets":true,"BlockPublicPolicy":true}},
	  {"Name":"shared","Policy":`+crossAccount+`},
	  {"Name":"acl-ignored","Acl":{"Grants":[{"Grantee":{"URI":"http://acs.amazonaws.com/groups/global/AllUsers"},"Permission":"READ"}]},
	   "c7n:PublicAccessBlock":{"IgnorePublicAcls":true}}]}]}`)
	byName := map[string]ontology.Node{}
	for _, n := range ev.Nodes {
		byName[n.Name] = n
	}
	if open := byName["open-by-policy"]; !open.Bool(ontology.PropPublicAccess) || open.Properties["public_via"] != "bucket policy" {
		t.Errorf("a policy granting s3:GetObject to * makes the bucket readable by anyone: %+v", open.Properties)
	}
	if byName["blocked"].Bool(ontology.PropInternetExposed) {
		t.Error("RestrictPublicBuckets keeps a public policy from taking effect")
	}
	if byName["shared"].Bool(ontology.PropInternetExposed) {
		t.Error("a policy naming one role makes nothing public")
	}
	if ignored := byName["acl-ignored"]; ignored.InternetExposed() || ignored.Properties["public_blocked_by"] != "IgnorePublicAcls (bucket)" {
		t.Errorf("IgnorePublicAcls voids a public ACL grant, and says so: %+v", ignored.Properties)
	}
	analytics := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::222222222222:role/analytics")
	granted := false
	for _, e := range ev.Edges {
		granted = granted || (e.Type == ontology.EdgeHasPermission && e.From == analytics &&
			e.To == ontology.NewID(ontology.LabelBucket, "shared"))
	}
	if !granted {
		t.Error("the role the bucket policy names in another account reaches the bucket")
	}
}

// Block Public Access set on the account closes every bucket in it, as S3 applies the
// stricter of the bucket's and the account's settings. Custodian reports the account's on
// an aws.account resource (the s3-public-block filter); the collector read only the
// bucket's, so a bucket an account-wide setting closes was reported open.
func TestTheAccountsBlockPublicAccessClosesItsBuckets(t *testing.T) {
	const public = `"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::b/*\"}]}"`
	const aclPublic = `{"Grants":[{"Grantee":{"URI":"http://acs.amazonaws.com/groups/global/AllUsers"},"Permission":"READ"}]}`
	accountPolicy := func(id, key, settings string) string {
		idField := ""
		if id != "" {
			idField = `"account_id":"` + id + `",`
		}
		return `{"resource":"aws.account","resources":[{` + idField + `"` + key + `":` + settings + `}]}`
	}
	buckets := `{"resource":"aws.s3","resources":[{"Name":"by-policy","Policy":` + public + `},{"Name":"by-acl","Acl":` + aclPublic + `}]}`
	restrict := `{"BlockPublicAcls":false,"IgnorePublicAcls":true,"BlockPublicPolicy":false,"RestrictPublicBuckets":true}`
	refuseNew := `{"BlockPublicAcls":true,"IgnorePublicAcls":false,"BlockPublicPolicy":true,"RestrictPublicBuckets":false}`

	for _, c := range []struct {
		name, bundle string
		open         bool
	}{
		{"no account settings in the export", `{"account_id":"` + account + `","policies":[` + buckets + `]}`, true},
		{"the account restricts public buckets and ignores public ACLs",
			`{"account_id":"` + account + `","policies":[` + buckets + `,` + accountPolicy(account, "c7n:s3-public-block", restrict) + `]}`, false},
		{"as the API returns them, the account policy first",
			`{"account_id":"` + account + `","policies":[` + accountPolicy(account, "PublicAccessBlockConfiguration", restrict) + `,` + buckets + `]}`, false},
		{"settings that only refuse new grants leave existing ones in force",
			`{"account_id":"` + account + `","policies":[` + buckets + `,` + accountPolicy(account, "c7n:s3-public-block", refuseNew) + `]}`, true},
		{"another account's settings",
			`{"account_id":"` + account + `","policies":[` + buckets + `,` + accountPolicy("210987654321", "c7n:s3-public-block", restrict) + `]}`, true},
		{"no account_id on the bundle, one account described",
			`{"policies":[` + buckets + `,` + accountPolicy(account, "c7n:s3-public-block", restrict) + `]}`, false},
		{"no account_id on the bundle, two accounts described",
			`{"policies":[` + buckets + `,` + accountPolicy(account, "c7n:s3-public-block", restrict) + `,` +
				accountPolicy("210987654321", "c7n:s3-public-block", `{}`) + `]}`, true},
	} {
		ev := parseBundle(t, c.bundle)
		for _, n := range ev.Nodes {
			if n.Label != ontology.LabelBucket {
				continue
			}
			if n.InternetExposed() != c.open || n.Bool(ontology.PropPublicAccess) != c.open {
				t.Errorf("%s: %s exposed=%v public=%v, want %v", c.name, n.Name, n.InternetExposed(), n.Bool(ontology.PropPublicAccess), c.open)
			}
			if _, written := n.Properties[ontology.PropNetworkExposed].(bool); !written {
				t.Errorf("%s: %s carries no exposure verdict, so a later closure could not retract it", c.name, n.Name)
			}
			if !c.open && !strings.Contains(fmt.Sprint(n.Properties["public_blocked_by"]), "(account)") {
				t.Errorf("%s: %s does not say the account's setting closed it: %v", c.name, n.Name, n.Properties["public_blocked_by"])
			}
		}
	}
}
