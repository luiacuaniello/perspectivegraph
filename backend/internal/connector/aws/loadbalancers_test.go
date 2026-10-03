package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const (
	lbArn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/"
	tgArn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/"
)

// fakeELB has two application load balancers on fakeEC2's network: "web", internet-facing
// in the public subnet behind the open web group, and "admin", internal. web forwards to an
// instance in the private subnet and to the ECS services registered in its workers group.
type fakeELB struct{}

func (fakeELB) DescribeLoadBalancers(context.Context, *elb.DescribeLoadBalancersInput, ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	lb := func(name string, scheme elbtypes.LoadBalancerSchemeEnum, subnet string) elbtypes.LoadBalancer {
		return elbtypes.LoadBalancer{LoadBalancerArn: aws.String(lbArn + name + "/1"), LoadBalancerName: aws.String(name),
			Type: elbtypes.LoadBalancerTypeEnumApplication, Scheme: scheme, IpAddressType: elbtypes.IpAddressTypeIpv4,
			SecurityGroups: []string{"sg-web"}, AvailabilityZones: []elbtypes.AvailabilityZone{{SubnetId: aws.String(subnet)}}}
	}
	return &elb.DescribeLoadBalancersOutput{LoadBalancers: []elbtypes.LoadBalancer{
		lb("web", elbtypes.LoadBalancerSchemeEnumInternetFacing, "subnet-pub"),
		lb("admin", elbtypes.LoadBalancerSchemeEnumInternal, "subnet-priv"),
	}}, nil
}

func (fakeELB) DescribeListeners(context.Context, *elb.DescribeListenersInput, ...func(*elb.Options)) (*elb.DescribeListenersOutput, error) {
	return &elb.DescribeListenersOutput{Listeners: []elbtypes.Listener{{Protocol: elbtypes.ProtocolEnumHttp, Port: aws.Int32(80)}}}, nil
}

func (fakeELB) DescribeTargetGroups(context.Context, *elb.DescribeTargetGroupsInput, ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error) {
	return &elb.DescribeTargetGroupsOutput{TargetGroups: []elbtypes.TargetGroup{
		{TargetGroupArn: aws.String(tgArn + "app/1"), TargetType: elbtypes.TargetTypeEnumInstance, Protocol: elbtypes.ProtocolEnumHttp,
			Port: aws.Int32(8080), LoadBalancerArns: []string{lbArn + "web/1"}},
		{TargetGroupArn: aws.String(tgArn + "workers/1"), TargetType: elbtypes.TargetTypeEnumIp, Protocol: elbtypes.ProtocolEnumHttp,
			Port: aws.Int32(9000), LoadBalancerArns: []string{lbArn + "web/1"}},
	}}, nil
}

func (fakeELB) DescribeTargetHealth(_ context.Context, in *elb.DescribeTargetHealthInput, _ ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error) {
	if aws.ToString(in.TargetGroupArn) != tgArn+"app/1" {
		return &elb.DescribeTargetHealthOutput{}, nil // the services' tasks come and go; none right now
	}
	return &elb.DescribeTargetHealthOutput{TargetHealthDescriptions: []elbtypes.TargetHealthDescription{
		{Target: &elbtypes.TargetDescription{Id: aws.String("i-lonely"), Port: aws.Int32(8080)}}}}, nil
}

// The connector reads load balancers and their targets: the internet-facing one is the way
// in, on the port its listener serves, and it reaches the private instance and the ECS
// services registered in its target group, with no task running.
func TestSDKReadsLoadBalancers(t *testing.T) {
	events, err := New(&sdkTransport{ec2: fakeEC2{}, iam: fakeIAM{}, ecs: fakeECS{}, elb: fakeELB{}}).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	byName, byID := map[string]ontology.Node{}, map[string]ontology.Node{}
	routes := map[string]string{}
	for _, ev := range events {
		for _, n := range ev.Nodes {
			byName[n.Name], byID[n.ID] = n, n
		}
	}
	for _, ev := range events {
		for _, e := range ev.Edges {
			if e.Type == ontology.EdgeRoutesTo {
				ports, _ := e.Properties["ports"].(string)
				routes[byID[e.From].Name+">"+byID[e.To].Name] = ports
			}
		}
	}
	if web := byName["web"]; web.Label != ontology.LabelLoadBalancer || !web.InternetExposed() || web.Properties["exposed_ports"] != "tcp/80" {
		t.Errorf("web is internet-facing in the public subnet, its listener on 80: %+v", web)
	}
	if byName["admin"].InternetExposed() {
		t.Error("an internal load balancer is no way in")
	}
	for route, ports := range map[string]string{"web>private-worker": "tcp/8080", "web>api": "tcp/9000", "web>worker": "tcp/9000"} {
		if got, ok := routes[route]; !ok || got != ports {
			t.Errorf("route %s on %q, got %q (present=%v); all: %v", route, ports, got, ok, routes)
		}
	}
}
