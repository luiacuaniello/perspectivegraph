package aws

import (
	"context"
	"net/url"
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
		{InstanceId: aws.String("i-web"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-web")}},
			Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("web-tier")}}},
		{InstanceId: aws.String("i-db"), SecurityGroups: []ec2types.GroupIdentifier{{GroupId: aws.String("sg-db")}},
			Tags: []ec2types.Tag{{Key: aws.String("Name"), Value: aws.String("customer-db")}, {Key: aws.String("classification"), Value: aws.String("pii")}}},
	}}}}, nil
}

func (fakeEC2) DescribeVpcPeeringConnections(context.Context, *ec2.DescribeVpcPeeringConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcPeeringConnectionsOutput, error) {
	return &ec2.DescribeVpcPeeringConnectionsOutput{}, nil
}

// fakeIAM returns one role with a URL-encoded trust + inline policy — exactly how
// the real GetAccountAuthorizationDetails encodes documents — to prove the iam
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
// 0.0.0.0/0 → internet-exposed node) and GAAD maps into iam events — no real AWS.
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
