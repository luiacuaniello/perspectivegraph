package aws

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

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
		// i-web sits in a PUBLIC subnet (IGW route) - genuinely internet-exposed.
		{InstanceId: aws.String("i-web"), SubnetId: aws.String("subnet-pub"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-web")}},
			Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("web-tier")}}},
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

// fakeIAM returns one role with a URL-encoded trust + inline policy - exactly how
// the real GetAccountAuthorizationDetails encodes documents - to prove the iam
// parser unescapes what our mapping emits.
type fakeIAM struct{}

func (fakeIAM) GetAccountAuthorizationDetails(context.Context, *iam.GetAccountAuthorizationDetailsInput, ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	trust := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	inline := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	return &iam.GetAccountAuthorizationDetailsOutput{
		RoleDetailList: []iamtypes.RoleDetail{{
			RoleName:                 aws.String("deployer"),
			Arn:                      aws.String("arn:aws:iam::123456789012:role/deployer"),
			AssumeRolePolicyDocument: aws.String(trust),
			RolePolicyList:           []iamtypes.PolicyDetail{{PolicyName: aws.String("inline"), PolicyDocument: aws.String(inline)}},
		}},
		IsTruncated: false,
	}, nil
}

// TestSDKMapping proves the SDK output → collector JSON conversion end-to-end with
// a fake client: the EC2 describe-* maps into cloudnet events (incl. the
// 0.0.0.0/0 → internet-exposed node) and GAAD maps into iam events - no real AWS.
func TestSDKMapping(t *testing.T) {
	c := New(&sdkTransport{ec2: fakeEC2{}, iam: fakeIAM{}})
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
