package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// fakeLambda has four functions: one with an open URL and the policy that opens it, one
// whose URL asks for IAM credentials, one with a URL without auth but no policy at all, and
// one whose URL was created in 2026 with the URL grant alone, which Lambda refuses.
type fakeLambda struct{}

const fnArn = "arn:aws:lambda:eu-west-1:123456789012:function:"

func (fakeLambda) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	fn := func(name string) lambdatypes.FunctionConfiguration {
		return lambdatypes.FunctionConfiguration{FunctionName: aws.String(name), FunctionArn: aws.String(fnArn + name),
			Role: aws.String("arn:aws:iam::123456789012:role/" + name + "-exec")}
	}
	return &lambda.ListFunctionsOutput{Functions: []lambdatypes.FunctionConfiguration{fn("open"), fn("iam-only"), fn("no-policy"), fn("new-url-only")}}, nil
}

func (fakeLambda) GetFunctionUrlConfig(_ context.Context, in *lambda.GetFunctionUrlConfigInput, _ ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error) {
	auth := lambdatypes.FunctionUrlAuthTypeNone
	if aws.ToString(in.FunctionName) == fnArn+"iam-only" {
		auth = lambdatypes.FunctionUrlAuthTypeAwsIam
	}
	created := "2024-03-01T09:00:00.000+0000"
	if aws.ToString(in.FunctionName) == fnArn+"new-url-only" {
		created = "2026-10-02T15:04:05.000+0000"
	}
	return &lambda.GetFunctionUrlConfigOutput{AuthType: auth, FunctionUrl: aws.String("https://x.lambda-url.eu-west-1.on.aws/"),
		CreationTime: aws.String(created)}, nil
}

func (fakeLambda) GetPolicy(_ context.Context, in *lambda.GetPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	if aws.ToString(in.FunctionName) == fnArn+"no-policy" {
		return nil, &lambdatypes.ResourceNotFoundException{Message: aws.String("no policy")}
	}
	return &lambda.GetPolicyOutput{Policy: aws.String(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl","Condition":{"StringEquals":{"lambda:FunctionUrlAuthType":"NONE"}}}]}`)}, nil
}

func (fakeLambda) ListTags(context.Context, *lambda.ListTagsInput, ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	return &lambda.ListTagsOutput{}, nil
}

// fakeECS has one cluster with two awsvpc services on fakeEC2's open web group and public
// subnet: one assigns a public address, one does not.
type fakeECS struct{}

func (fakeECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:eu-west-1:123456789012:cluster/prod"}}, nil
}

func (fakeECS) ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	return &ecs.ListServicesOutput{ServiceArns: []string{
		"arn:aws:ecs:eu-west-1:123456789012:service/prod/api", "arn:aws:ecs:eu-west-1:123456789012:service/prod/worker"}}, nil
}

func (fakeECS) DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	svc := func(name string, public ecstypes.AssignPublicIp) ecstypes.Service {
		return ecstypes.Service{ServiceArn: aws.String("arn:aws:ecs:eu-west-1:123456789012:service/prod/" + name),
			ServiceName: aws.String(name), TaskDefinition: aws.String("arn:aws:ecs:eu-west-1:123456789012:task-definition/app:1"),
			NetworkConfiguration: &ecstypes.NetworkConfiguration{AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
				AssignPublicIp: public, SecurityGroups: []string{"sg-web"}, Subnets: []string{"subnet-pub"}}}}
	}
	return &ecs.DescribeServicesOutput{Services: []ecstypes.Service{
		svc("api", ecstypes.AssignPublicIpEnabled), svc("worker", ecstypes.AssignPublicIpDisabled)}}, nil
}

func (fakeECS) DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{
		TaskRoleArn: aws.String("arn:aws:iam::123456789012:role/app-task")}}, nil
}

// The connector reads Lambda functions and ECS services: a function is open only when its
// URL needs no auth AND its policy lets anyone in; a service is exposed by the same rules
// as an instance; both hold their roles.
func TestSDKReadsLambdaAndECS(t *testing.T) {
	events, err := New(&sdkTransport{ec2: fakeEC2{}, iam: fakeIAM{}, lambda: fakeLambda{}, ecs: fakeECS{}}).Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	byName := map[string]ontology.Node{}
	roleOf := map[string]string{}
	byID := map[string]ontology.Node{}
	for _, ev := range events {
		for _, n := range ev.Nodes {
			byName[n.Name] = n
			byID[n.ID] = n
		}
	}
	for _, ev := range events {
		for _, e := range ev.Edges {
			if e.Type == ontology.EdgeAssumes {
				roleOf[byID[e.From].Name] = byID[e.To].Name
			}
		}
	}
	for name, want := range map[string]bool{"open": true, "iam-only": false, "no-policy": false, "new-url-only": false, "api": true, "worker": false} {
		if got := byName[name].InternetExposed(); got != want {
			t.Errorf("%s exposed = %v, want %v (%v)", name, got, want, byName[name].Properties["exposure"])
		}
	}
	if byName["open"].Label != ontology.LabelFunction {
		t.Errorf("a Lambda function is a Function, got %s", byName["open"].Label)
	}
	for workload, role := range map[string]string{"open": "open-exec", "api": "app-task"} {
		if roleOf[workload] != role {
			t.Errorf("%s assumes %q, want %s", workload, roleOf[workload], role)
		}
	}
}
