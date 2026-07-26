package iam

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The permissions-boundary lab, as a fixture: two roles with a BYTE-IDENTICAL inline
// policy granting real privesc primitives account-wide, differing only in whether a
// boundary is attached. The boundary allows just s3:Get*/ec2:Describe*, so the
// intersection strips the privesc grant - with no explicit Deny anywhere, which is how
// boundaries are used in practice and precisely the case a reader of identity policies
// alone gets wrong.
//
// This is the shape `make boundary-lab-aws` builds on a live account, where AWS's own
// SimulatePrincipalPolicy allows the unbounded role and denies the bounded one. Keeping
// it here means the regression is caught by `make test`, not only by an account.
const boundaryLabBundle = `{
  "RoleDetailList": [
    {
      "RoleName": "unbounded",
      "Arn": "arn:aws:iam::1:role/unbounded",
      "RolePolicyList": [{"PolicyName":"privesc","PolicyDocument":{"Statement":[
        {"Effect":"Allow","Action":["iam:AttachUserPolicy","iam:PutUserPolicy","iam:CreateAccessKey"],"Resource":"*"}]}}]
    },
    {
      "RoleName": "bounded",
      "Arn": "arn:aws:iam::1:role/bounded",
      "RolePolicyList": [{"PolicyName":"privesc","PolicyDocument":{"Statement":[
        {"Effect":"Allow","Action":["iam:AttachUserPolicy","iam:PutUserPolicy","iam:CreateAccessKey"],"Resource":"*"}]}}],
      "PermissionsBoundary": {"PermissionsBoundaryType":"Policy","PermissionsBoundaryArn":"arn:aws:iam::1:policy/boundary"}
    }
  ],
  "Policies": [{
    "PolicyName": "boundary",
    "Arn": "arn:aws:iam::1:policy/boundary",
    "DefaultVersionId": "v1",
    "PolicyVersionList": [{"VersionId":"v1","IsDefaultVersion":true,"Document":{"Statement":[
      {"Effect":"Allow","Action":["s3:Get*","ec2:Describe*"],"Resource":"*"}]}}]
  }]
}`

// parseRoles runs the collector and indexes the roles by name alongside their
// escalation edge, since every assertion below is about one or the other.
func parseRoles(t *testing.T, bundle string) (map[string]ontology.Node, map[string]ontology.Edge) {
	t.Helper()
	events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byID := map[string]ontology.Node{}
	nodes := map[string]ontology.Node{}
	for _, ev := range events {
		for _, n := range ev.Nodes {
			byID[n.ID] = n
			nodes[n.Name] = n
		}
	}
	edges := map[string]ontology.Edge{}
	for _, ev := range events {
		for _, e := range ev.Edges {
			if e.Type == ontology.EdgeCanEscalateTo {
				edges[byID[e.From].Name] = e
			}
		}
	}
	return nodes, edges
}

// TestPermissionsBoundaryCapsEscalation is the regression for the engine's first
// demonstrated false positive, reproduced live on AWS account 231016596764: the engine
// emitted CAN_ESCALATE_TO for BOTH roles while SimulatePrincipalPolicy allowed only the
// unbounded one. The unbounded role is the control - without it a "fix" that simply
// stopped emitting escalation edges would pass this test.
func TestPermissionsBoundaryCapsEscalation(t *testing.T) {
	nodes, edges := parseRoles(t, boundaryLabBundle)

	if _, ok := edges["unbounded"]; !ok {
		t.Error("the unbounded role holds iam:AttachUserPolicy on * and must still escalate")
	}
	if e, ok := edges["bounded"]; ok {
		t.Errorf("the boundary permits no iam: action, so the intersection cannot escalate; got an edge at p=%.2f (%v)",
			e.ExploitProbability, e.Properties["primitives"])
	}

	// The boundary belongs on the graph as evidence: a verdict that changed for reasons
	// the graph cannot show is not auditable.
	if got := nodes["bounded"].Properties[propPermissionsBoundary]; got != "arn:aws:iam::1:policy/boundary" {
		t.Errorf("bounded role %s = %v, want the boundary ARN", propPermissionsBoundary, got)
	}
	if _, ok := nodes["unbounded"].Properties[propPermissionsBoundary]; ok {
		t.Error("the unbounded role has no boundary and must not carry the property")
	}
}

// TestBoundaryDoesNotGrant pins the half of the semantics that is easy to get
// backwards: a boundary caps, it never grants. A principal whose boundary allows
// iam:AttachUserPolicy but whose identity policy does not must hold nothing - if a
// boundary could grant, attaching a permissive boundary would manufacture escalations
// out of nowhere.
func TestBoundaryDoesNotGrant(t *testing.T) {
	boundary := actionSet{}.add("iam:*")

	empty := actionSet{}.cappedBy(boundary)
	if empty.Allows("iam:AttachUserPolicy") {
		t.Error("a boundary must not grant an action the identity policy never allowed")
	}
	if len(detectPrivesc(empty)) != 0 {
		t.Error("a boundary alone must yield no privesc primitive")
	}
	if empty.IsAdmin() {
		t.Error("a boundary alone must not make a principal admin")
	}

	// And the intersection with a real grant is the grant, not more.
	both := actionSet{}.add("iam:AttachUserPolicy").cappedBy(boundary)
	if !both.Allows("iam:AttachUserPolicy") {
		t.Error("an action both sides allow must survive the intersection")
	}
	if both.Allows("iam:CreateAccessKey") {
		t.Error("the boundary allows iam:* but the identity policy does not; the intersection must not")
	}
}

// TestBoundaryIntersectionSemantics covers the cases the lab does not: a boundary that
// is a no-op, one that revokes admin, and one that narrows an account-wide grant to
// specific resources.
func TestBoundaryIntersectionSemantics(t *testing.T) {
	t.Run("AdministratorAccess boundary is a no-op", func(t *testing.T) {
		// The most common boundary in the wild. Treating "bounded" as "safe" would turn
		// this into a false negative, which is worse than the bug being fixed.
		a := actionSet{}.add("iam:AttachUserPolicy").cappedBy(actionSet{}.add("*"))
		if !a.Allows("iam:AttachUserPolicy") {
			t.Error("an admin-equivalent boundary caps nothing and must leave the primitive intact")
		}
		if len(detectPrivesc(a)) == 0 {
			t.Error("a no-op boundary must not suppress the escalation")
		}
	})

	t.Run("boundary revokes admin", func(t *testing.T) {
		if (actionSet{}.add("*").cappedBy(actionSet{}.add("s3:Get*"))).IsAdmin() {
			t.Error("Allow *:* under a read-only boundary is not admin: the intersection is read-only")
		}
		if !(actionSet{}.add("*").cappedBy(actionSet{}.add("*"))).IsAdmin() {
			t.Error("Allow *:* under an admin boundary is still admin")
		}
	})

	t.Run("boundary Deny beats the identity Allow", func(t *testing.T) {
		a := actionSet{}.add("iam:*").cappedBy(actionSet{}.add("*").deny("iam:AttachUserPolicy"))
		if a.Allows("iam:AttachUserPolicy") {
			t.Error("an explicit Deny inside the boundary must block the action")
		}
		if !a.Allows("iam:PutUserPolicy") {
			t.Error("the boundary Deny is action-specific and must not block everything")
		}
	})

	t.Run("boundary narrows an account-wide grant to scoped", func(t *testing.T) {
		// Identity allows the primitive account-wide; the boundary permits it only on
		// specific resources. The escalation is real but contingent on those targets, so
		// it must land in the same lower-confidence bucket as a resource-scoped grant
		// rather than being asserted at full probability.
		a := actionSet{}.add("iam:AttachUserPolicy").cappedBy(actionSet{}.addScoped("iam:AttachUserPolicy"))
		if !a.Allows("iam:AttachUserPolicy") {
			t.Fatal("the action is permitted by both sides and must survive")
		}
		if a.BroadlyAllows("iam:AttachUserPolicy") {
			t.Error("a boundary that permits the action only on specific resources must not read as account-wide")
		}
		matches := detectPrivesc(a)
		if len(matches) == 0 {
			t.Fatal("a boundary-narrowed grant is still a real primitive, not a miss")
		}
		if !matches[0].ScopedOnly {
			t.Error("a boundary-narrowed primitive must be flagged scoped")
		}
	})
}

// TestUnresolvedBoundaryIsReportedUnverified covers the input the connector cannot
// always avoid: an uploaded authorization-details dump that names a boundary by ARN
// but does not carry its document. We know a cap exists and not what it permits, so
// dropping the edge would miss the common AdministratorAccess no-op boundary, and
// asserting it at full confidence would repeat the original overclaim. It stays, marked
// and scored down.
func TestUnresolvedBoundaryIsReportedUnverified(t *testing.T) {
	// The same fixture with the boundary's document removed from Policies.
	bundle := strings.Replace(boundaryLabBundle,
		`"Arn": "arn:aws:iam::1:policy/boundary"`, `"Arn": "arn:aws:iam::1:policy/some-other-policy"`, 1)

	nodes, edges := parseRoles(t, bundle)

	e, ok := edges["bounded"]
	if !ok {
		t.Fatal("an unreadable boundary must not silently delete the escalation: that would miss a no-op AdministratorAccess boundary")
	}
	if e.ExploitProbability != unresolvedBoundaryProb {
		t.Errorf("probability = %.2f, want %.2f (unverified, not established)", e.ExploitProbability, unresolvedBoundaryProb)
	}
	if e.Properties[propBoundaryUnresolved] != true {
		t.Errorf("the edge must carry %s so the claim cannot be quoted as verified", propBoundaryUnresolved)
	}
	if nodes["bounded"].Properties[propBoundaryUnresolved] != true {
		t.Errorf("the node must carry %s too", propBoundaryUnresolved)
	}

	// The control is unaffected: no boundary, no downgrade.
	if e := edges["unbounded"]; e.ExploitProbability != privescProb {
		t.Errorf("unbounded probability = %.2f, want %.2f", e.ExploitProbability, privescProb)
	}
}

// TestResolvedBoundaryOnASurvivingEscalationIsEvidence: when a boundary is read and
// simply does not cap the matched primitives, the edge must say so. "Checked and still
// escalates" and "never checked" are different claims and must not look identical on
// the graph.
func TestResolvedBoundaryOnASurvivingEscalationIsEvidence(t *testing.T) {
	bundle := strings.Replace(boundaryLabBundle,
		`{"Effect":"Allow","Action":["s3:Get*","ec2:Describe*"],"Resource":"*"}`,
		`{"Effect":"Allow","Action":"*","Resource":"*"}`, 1)

	_, edges := parseRoles(t, bundle)

	e, ok := edges["bounded"]
	if !ok {
		t.Fatal("an AdministratorAccess-equivalent boundary caps nothing; the escalation must survive")
	}
	if e.ExploitProbability != privescProb {
		t.Errorf("probability = %.2f, want %.2f: a boundary that caps nothing must not lower the score",
			e.ExploitProbability, privescProb)
	}
	if e.Properties["boundary_evaluated"] != true {
		t.Error("a surviving escalation behind a boundary that was actually intersected must record that it was")
	}
	if e.Properties[propBoundaryUnresolved] == true {
		t.Error("the boundary was resolved; it must not be reported unresolved")
	}
}

// TestUserPermissionsBoundary: boundaries apply to users exactly as they do to roles,
// including over permissions inherited from a group. A user is the credential-origin
// seed, so a boundary missed here is a false positive on the path the engine reports
// when SEED_IAM_USERS is on.
func TestUserPermissionsBoundary(t *testing.T) {
	const bundle = `{
	  "UserDetailList": [{
	    "UserName": "capped",
	    "Arn": "arn:aws:iam::1:user/capped",
	    "GroupList": ["admins"],
	    "PermissionsBoundary": {"PermissionsBoundaryType":"Policy","PermissionsBoundaryArn":"arn:aws:iam::1:policy/boundary"}
	  }],
	  "GroupDetailList": [{
	    "GroupName": "admins",
	    "Arn": "arn:aws:iam::1:group/admins",
	    "GroupPolicyList": [{"PolicyName":"admin","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}]
	  }],
	  "Policies": [{
	    "PolicyName": "boundary",
	    "Arn": "arn:aws:iam::1:policy/boundary",
	    "DefaultVersionId": "v1",
	    "PolicyVersionList": [{"VersionId":"v1","IsDefaultVersion":true,"Document":{"Statement":[
	      {"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}}]
	  }]
	}`

	nodes, edges := parseRoles(t, bundle)

	if e, ok := edges["capped"]; ok {
		t.Errorf("the group grants Allow *:* but the boundary caps to s3:Get*; the user is not admin (got p=%.2f, %v)",
			e.ExploitProbability, e.Properties["reason"])
	}
	if got := nodes["capped"].Properties[propPermissionsBoundary]; got != "arn:aws:iam::1:policy/boundary" {
		t.Errorf("user %s = %v, want the boundary ARN", propPermissionsBoundary, got)
	}
}
