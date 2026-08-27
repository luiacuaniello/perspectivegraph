package aws

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// fakeEC2 returns a tiny but representative topology: an internet-open SG, an
// SG-to-SG rule, and two instances (one a PII-tagged crown jewel).
type fakeEC2 struct{}

func (fakeEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []ec2types.SecurityGroup{
		{GroupId: aws.String("sg-web"), GroupName: aws.String("web-sg"), IpPermissions: []ec2types.IpPermission{
			{IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},
		}},
		{GroupId: aws.String("sg-db"), GroupName: aws.String("db-sg"), IpPermissions: []ec2types.IpPermission{
			{UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: aws.String("sg-web")}}},
		}},
	}}, nil
}

func (fakeEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
		// i-web sits in a PUBLIC subnet (IGW route) - genuinely internet-exposed. It carries
		// an instance profile (the role an attacker inherits via IMDS) and still answers
		// IMDSv1, so a blind SSRF suffices.
		{InstanceId: aws.String("i-web"), SubnetId: aws.String("subnet-pub"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-web")}},
			IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: aws.String("arn:aws:iam::123456789012:instance-profile/web-profile")},
			MetadataOptions:    &ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensStateOptional},
			Tags:               []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("web-tier")}}},
		// i-lonely has the SAME open SG but sits in a PRIVATE subnet (NAT only) - the
		// false positive the route/NACL layer removes.
		{InstanceId: aws.String("i-lonely"), SubnetId: aws.String("subnet-priv"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-web")}},
			Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("private-worker")}}},
		{InstanceId: aws.String("i-db"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-db")}},
			Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("customer-db")}, {Key: aws.String("classification"), Value: aws.String("pii")}}},
		// A terminated instance is still returned by DescribeInstances for a while but has
		// no live network presence - the connector must drop it, not emit a phantom seed.
		{InstanceId: aws.String("i-ghost"), SubnetId: aws.String("subnet-pub"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-web")}},
			State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameTerminated},
			Tags:  []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("terminated-box")}}},
	}}}}, nil
}

func (fakeEC2) DescribeVpcPeeringConnections(context.Context, *ec2.DescribeVpcPeeringConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcPeeringConnectionsOutput, error) {
	return &ec2.DescribeVpcPeeringConnectionsOutput{}, nil
}

func (fakeEC2) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return &ec2.DescribeRouteTablesOutput{RouteTables: []ec2types.RouteTable{
		{RouteTableId: aws.String("rt-pub"), VpcId: aws.String("vpc-1"),
			Routes:       []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: aws.String("igw-1")}},
			Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String("subnet-pub")}}},
		{RouteTableId: aws.String("rt-priv"), VpcId: aws.String("vpc-1"),
			Routes:       []ec2types.Route{{DestinationCidrBlock: aws.String("0.0.0.0/0"), NatGatewayId: aws.String("nat-1")}},
			Associations: []ec2types.RouteTableAssociation{{SubnetId: aws.String("subnet-priv")}}},
	}}, nil
}

func (fakeEC2) DescribeNetworkAcls(context.Context, *ec2.DescribeNetworkAclsInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	return &ec2.DescribeNetworkAclsOutput{NetworkAcls: []ec2types.NetworkAcl{
		{NetworkAclId: aws.String("acl-default"),
			Entries:      []ec2types.NetworkAclEntry{{RuleNumber: aws.Int32(100), Egress: aws.Bool(false), CidrBlock: aws.String("0.0.0.0/0"), RuleAction: ec2types.RuleActionAllow}},
			Associations: []ec2types.NetworkAclAssociation{{SubnetId: aws.String("subnet-pub")}, {SubnetId: aws.String("subnet-priv")}}},
	}}, nil
}

func (fakeEC2) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return &ec2.DescribeSubnetsOutput{Subnets: []ec2types.Subnet{
		{SubnetId: aws.String("subnet-pub"), VpcId: aws.String("vpc-1")},
		{SubnetId: aws.String("subnet-priv"), VpcId: aws.String("vpc-1")},
	}}, nil
}

// fakeIAM returns two roles with a URL-encoded trust + inline policy - exactly how
// the real GetAccountAuthorizationDetails encodes documents - to prove the iam
// parser unescapes what our mapping emits. Its ListInstanceProfiles resolves i-web's
// profile to the `deployer` role, which is what joins the network graph to the
// identity graph.
//
// The second role, `bounded-deployer`, carries the SAME admin inline policy behind a
// permissions boundary, and the boundary's document is served only by
// GetPolicy/GetPolicyVersion - never in the bundle's Policies list. That is the real
// account's shape: a boundary policy attached to nothing else need not come back with
// the authorization details, so a connector that does not fetch it cannot intersect it.
type fakeSTS struct{ account string }

func (f fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account)}, nil
}

type fakeIAM struct{}

const (
	fakeBoundaryARN = "arn:aws:iam::123456789012:policy/read-only-boundary"
	// The boundary omits every iam: action, so the intersection strips the admin
	// grant - no explicit Deny, which is how boundaries are actually used.
	fakeBoundaryDoc = `{"Statement":[{"Effect":"Allow","Action":["s3:Get*","ec2:Describe*"],"Resource":"*"}]}`
)

func (fakeIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if aws.ToString(in.PolicyArn) != fakeBoundaryARN {
		return nil, fmt.Errorf("unexpected policy arn %q", aws.ToString(in.PolicyArn))
	}
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
		Arn:              aws.String(fakeBoundaryARN),
		PolicyName:       aws.String("read-only-boundary"),
		DefaultVersionId: aws.String("v1"),
	}}, nil
}

func (fakeIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	if aws.ToString(in.PolicyArn) != fakeBoundaryARN {
		return nil, fmt.Errorf("unexpected policy arn %q", aws.ToString(in.PolicyArn))
	}
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		VersionId:        aws.String("v1"),
		IsDefaultVersion: true,
		Document:         aws.String(url.QueryEscape(fakeBoundaryDoc)),
	}}, nil
}

func (fakeIAM) ListInstanceProfiles(context.Context, *iam.ListInstanceProfilesInput, ...func(*iam.Options)) (*iam.ListInstanceProfilesOutput, error) {
	return &iam.ListInstanceProfilesOutput{InstanceProfiles: []iamtypes.InstanceProfile{{
		Arn: aws.String("arn:aws:iam::123456789012:instance-profile/web-profile"),
		Roles: []iamtypes.Role{{
			Arn:      aws.String("arn:aws:iam::123456789012:role/deployer"),
			RoleName: aws.String("deployer"),
		}},
	}}}, nil
}

func (fakeIAM) GetAccountAuthorizationDetails(context.Context, *iam.GetAccountAuthorizationDetailsInput, ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	trust := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	inline := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	return &iam.GetAccountAuthorizationDetailsOutput{
		RoleDetailList: []iamtypes.RoleDetail{{
			RoleName:                 aws.String("deployer"),
			Arn:                      aws.String("arn:aws:iam::123456789012:role/deployer"),
			AssumeRolePolicyDocument: aws.String(trust),
			RolePolicyList:           []iamtypes.PolicyDetail{{PolicyName: aws.String("inline"), PolicyDocument: aws.String(inline)}},
		}, {
			RoleName:                 aws.String("bounded-deployer"),
			Arn:                      aws.String("arn:aws:iam::123456789012:role/bounded-deployer"),
			AssumeRolePolicyDocument: aws.String(trust),
			RolePolicyList:           []iamtypes.PolicyDetail{{PolicyName: aws.String("inline"), PolicyDocument: aws.String(inline)}},
			PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{
				PermissionsBoundaryType: iamtypes.PermissionsBoundaryAttachmentTypePolicy,
				PermissionsBoundaryArn:  aws.String(fakeBoundaryARN),
			},
		}},
		IsTruncated: false,
	}, nil
}

// TestSDKMapping proves the SDK output → collector JSON conversion end-to-end with
// a fake client: the EC2 describe-* maps into cloudnet events (incl. the
// 0.0.0.0/0 → internet-exposed node) and GAAD maps into iam events - no real AWS.
func TestSDKMapping(t *testing.T) {
	c := New(&sdkTransport{ec2: fakeEC2{}, iam: fakeIAM{}, sts: fakeSTS{account: "123456789012"}})
	if c.Mode() != "sdk" {
		t.Fatalf("mode = %q, want sdk", c.Mode())
	}

	events, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	bySource := map[string]int{}
	internet := false
	nodes := 0
	for _, ev := range events {
		bySource[ev.Source]++
		for _, n := range ev.Nodes {
			nodes++
			if b, ok := n.Properties[ontology.PropInternetExposed].(bool); ok && b {
				internet = true
			}
		}
	}
	if bySource["cloudnet"] == 0 {
		t.Error("expected cloudnet events from the EC2 mapping")
	}
	if bySource["iam"] == 0 {
		t.Error("expected iam events from the GAAD mapping")
	}
	if nodes == 0 {
		t.Error("expected the mapped JSON to parse into nodes")
	}
	if !internet {
		t.Error("the 0.0.0.0/0 security group should have produced an internet-exposed node")
	}
}

// TestSDKInstanceProfileJoinsNetworkAndIdentity guards the gap that only real-account
// validation exposed: EC2 reports an instance's IAM *instance profile*, never the role
// behind it, so without resolving the profile the network graph and the identity graph
// stay disconnected and the canonical AWS path - internet → instance → IMDS → role →
// privilege escalation - cannot form at all. The ASSUMES edge must land on the SAME node
// the iam collector builds (both key roles by ARN), which is what fuses the two halves.
func TestSDKInstanceProfileJoinsNetworkAndIdentity(t *testing.T) {
	events, err := New(&sdkTransport{ec2: fakeEC2{}, iam: fakeIAM{}}).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	var (
		vmID    = ontology.NewID(ontology.LabelVirtualMachine, "i-web")
		roleID  = ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::123456789012:role/deployer")
		edgeP   = -1.0
		fromIAM bool
	)
	for _, ev := range events {
		for _, e := range ev.Edges {
			if e.Type == ontology.EdgeAssumes && e.From == vmID && e.To == roleID {
				edgeP = e.ExploitProbability
			}
		}
		// The iam feed must independently produce a node with that same id - proof the two
		// collectors converge rather than making parallel, unlinked roles.
		if ev.Source == "iam" {
			for _, n := range ev.Nodes {
				if n.ID == roleID {
					fromIAM = true
				}
			}
		}
	}
	if edgeP < 0 {
		t.Fatal("missing i-web --ASSUMES--> deployer: the network and identity halves stay disconnected")
	}
	if edgeP != 0.9 {
		t.Errorf("ASSUMES probability = %v, want 0.9 (IMDSv1 optional: a blind SSRF reads the credentials)", edgeP)
	}
	if !fromIAM {
		t.Error("the iam collector did not produce the same role node id - the halves would not fuse")
	}
}

// TestSDKCarriesPermissionsBoundary closes the false positive the boundary lab
// demonstrated on a live account (231016596764): two roles with a byte-identical
// admin grant, differing only in a permissions boundary, were reported as equally
// able to reach account-admin because `GetAccountAuthorizationDetails` returns the
// boundary and the connector's role struct dropped it before ingestion.
//
// The whole chain is under test here: the SDK mapping keeps `PermissionsBoundary`,
// the transport fetches the boundary document that the bundle did not carry, and the
// iam collector intersects it - so only the unbounded role keeps the escalation edge.
func TestSDKCarriesPermissionsBoundary(t *testing.T) {
	events, err := New(&sdkTransport{ec2: fakeEC2{}, iam: fakeIAM{}}).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	var (
		unbounded = ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::123456789012:role/deployer")
		bounded   = ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::123456789012:role/bounded-deployer")
	)
	escalates := map[string]bool{}
	nodesByID := map[string]ontology.Node{}
	for _, ev := range events {
		for _, n := range ev.Nodes {
			nodesByID[n.ID] = n
		}
		for _, e := range ev.Edges {
			if e.Type == ontology.EdgeCanEscalateTo {
				escalates[e.From] = true
			}
		}
	}

	if !escalates[unbounded] {
		t.Error("the unbounded role holds Allow *:* and must still reach account-admin - the control, without which a fix that simply drops every escalation would pass")
	}
	if escalates[bounded] {
		t.Error("the bounded role's boundary permits no iam: action, so the intersection cannot escalate: this is the demonstrated false positive")
	}
	// The boundary must reach the graph as evidence, not just silently change a verdict.
	if got := nodesByID[bounded].Properties["permissions_boundary"]; got != fakeBoundaryARN {
		t.Errorf("bounded role permissions_boundary = %v, want %s", got, fakeBoundaryARN)
	}
	if nodesByID[bounded].Properties["permissions_boundary_unresolved"] == true {
		t.Error("the transport fetched the boundary document, so it must not be reported unresolved")
	}
}

// TestSDKRouteNaclPrecision proves the connector now fetches route tables + NACLs and
// resolves each subnet, so the collector gates exposure on real reachability: two
// instances share the same 0.0.0.0/0 SG, but only the one in a public subnet (IGW
// route) is internet-exposed - the private-subnet one (NAT only) is not. No real AWS.
func TestSDKRouteNaclPrecision(t *testing.T) {
	events, err := New(&sdkTransport{ec2: fakeEC2{}, iam: fakeIAM{}}).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	exposedByName := map[string]bool{}
	nodesByName := map[string]ontology.Node{}
	for _, ev := range events {
		for _, n := range ev.Nodes {
			nodesByName[n.Name] = n
			if b, ok := n.Properties[ontology.PropInternetExposed].(bool); ok && b {
				exposedByName[n.Name] = true
			}
		}
	}
	if !exposedByName["web-tier"] {
		t.Error("web-tier (public subnet, IGW route) should be internet-exposed")
	}
	if exposedByName["private-worker"] {
		t.Error("private-worker (same open SG but a private subnet, NAT only) must NOT be internet-exposed")
	}
	// The private-worker note should name the NAT gateway (proving the SDK now carries
	// NatGatewayId, not a blank GatewayId, for a real NAT default route).
	if note, _ := nodesByName["private-worker"].Properties["net_reachability"].(string); !strings.Contains(note, "NAT gateway") {
		t.Errorf("private-worker net_reachability = %q, want it to name the NAT gateway", note)
	}
	// The terminated instance must not appear at all.
	if _, ok := nodesByName["terminated-box"]; ok {
		t.Error("a terminated instance must be dropped, not emitted as a node")
	}
}
