package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// lambdaAPI is the slice of Lambda the connector reads: the functions, their URLs, their
// resource policies and their tags. All of it is inside SecurityAudit.
type lambdaAPI interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetFunctionUrlConfig(context.Context, *lambda.GetFunctionUrlConfigInput, ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error)
	GetPolicy(context.Context, *lambda.GetPolicyInput, ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
	ListTags(context.Context, *lambda.ListTagsInput, ...func(*lambda.Options)) (*lambda.ListTagsOutput, error)
}

// ecsAPI is the slice of ECS the connector reads: services, their network configuration
// and the task role of their task definition. All of it is inside SecurityAudit.
type ecsAPI interface {
	ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

type lambdaBundle struct {
	Functions []lambdaFunction `json:"functions"`
}

type lambdaFunction struct {
	FunctionName string            `json:"FunctionName"`
	FunctionArn  string            `json:"FunctionArn"`
	Role         string            `json:"Role,omitempty"`
	URL          *lambdaURL        `json:"Url,omitempty"`
	Policy       string            `json:"Policy"`
	Tags         map[string]string `json:"Tags,omitempty"`
}

type lambdaURL struct {
	AuthType    string `json:"AuthType"`
	FunctionURL string `json:"FunctionUrl"`
}

// noPolicy is the policy of a function that has none: read, and empty - which is not the
// same as unread. A function URL without authentication still needs a policy that lets
// every principal invoke it, so a function with none is not open.
const noPolicy = `{"Statement":[]}`

// fetchLambda reads every function in the region with its URL, its resource policy and
// its tags.
func (t *sdkTransport) fetchLambda(ctx context.Context) ([]byte, error) {
	if t.lambda == nil {
		return nil, nil
	}
	var b lambdaBundle
	var marker *string
	for {
		out, err := t.lambda.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list lambda functions: %w", err)
		}
		for _, fn := range out.Functions {
			f := lambdaFunction{FunctionName: aws.ToString(fn.FunctionName), FunctionArn: aws.ToString(fn.FunctionArn),
				Role: aws.ToString(fn.Role), Policy: noPolicy}
			url, err := t.lambda.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{FunctionName: fn.FunctionArn})
			switch {
			case err == nil:
				f.URL = &lambdaURL{AuthType: string(url.AuthType), FunctionURL: aws.ToString(url.FunctionUrl)}
			case !notFound(err):
				return nil, fmt.Errorf("function url of %s: %w", f.FunctionName, err)
			}
			pol, err := t.lambda.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: fn.FunctionArn})
			switch {
			case err == nil:
				f.Policy = aws.ToString(pol.Policy)
			case !notFound(err):
				return nil, fmt.Errorf("policy of %s: %w", f.FunctionName, err)
			}
			if tags, err := t.lambda.ListTags(ctx, &lambda.ListTagsInput{Resource: fn.FunctionArn}); err == nil {
				f.Tags = tags.Tags
			}
			b.Functions = append(b.Functions, f)
		}
		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	if len(b.Functions) == 0 {
		return nil, nil
	}
	return json.Marshal(b)
}

// notFound reports Lambda's "this function has no such thing": no URL, no policy.
func notFound(err error) bool {
	var nf *lambdatypes.ResourceNotFoundException
	return errors.As(err, &nf)
}

// ecsServiceJSON is one ECS service in awsvpc mode, flattened into the network bundle.
type ecsServiceJSON struct {
	ServiceArn     string   `json:"serviceArn"`
	ServiceName    string   `json:"serviceName"`
	ClusterArn     string   `json:"clusterArn"`
	TaskRoleArn    string   `json:"taskRoleArn,omitempty"`
	AssignPublicIP string   `json:"assignPublicIp,omitempty"`
	SecurityGroups []string `json:"securityGroups,omitempty"`
	Subnets        []string `json:"subnets,omitempty"`
}

// ecsServices reads every ECS service in the region that runs in awsvpc mode - the mode
// with its own security groups - and the task role of its task definition.
func (t *sdkTransport) ecsServices(ctx context.Context) ([]ecsServiceJSON, error) {
	if t.ecs == nil {
		return nil, nil
	}
	var out []ecsServiceJSON
	taskRoles := map[string]string{} // task definition ARN -> task role ARN
	var cnext *string
	for {
		clusters, err := t.ecs.ListClusters(ctx, &ecs.ListClustersInput{NextToken: cnext})
		if err != nil {
			return nil, fmt.Errorf("list ecs clusters: %w", err)
		}
		for _, cluster := range clusters.ClusterArns {
			var arns []string
			var snext *string
			for {
				page, err := t.ecs.ListServices(ctx, &ecs.ListServicesInput{Cluster: aws.String(cluster), NextToken: snext})
				if err != nil {
					return nil, fmt.Errorf("list services of %s: %w", cluster, err)
				}
				arns = append(arns, page.ServiceArns...)
				if page.NextToken == nil {
					break
				}
				snext = page.NextToken
			}
			for i := 0; i < len(arns); i += 10 { // DescribeServices takes ten at a time
				batch := arns[i:min(i+10, len(arns))]
				desc, err := t.ecs.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: aws.String(cluster), Services: batch})
				if err != nil {
					return nil, fmt.Errorf("describe services of %s: %w", cluster, err)
				}
				for _, s := range desc.Services {
					nc := s.NetworkConfiguration
					if nc == nil || nc.AwsvpcConfiguration == nil {
						continue // bridge or host networking: no security groups of its own
					}
					svc := ecsServiceJSON{ServiceArn: aws.ToString(s.ServiceArn), ServiceName: aws.ToString(s.ServiceName),
						ClusterArn: cluster, AssignPublicIP: string(nc.AwsvpcConfiguration.AssignPublicIp),
						SecurityGroups: nc.AwsvpcConfiguration.SecurityGroups, Subnets: nc.AwsvpcConfiguration.Subnets}
					if td := aws.ToString(s.TaskDefinition); td != "" {
						role, seen := taskRoles[td]
						if !seen {
							def, err := t.ecs.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(td)})
							if err != nil {
								return nil, fmt.Errorf("describe task definition %s: %w", td, err)
							}
							if def.TaskDefinition != nil {
								role = aws.ToString(def.TaskDefinition.TaskRoleArn)
							}
							taskRoles[td] = role
						}
						svc.TaskRoleArn = role
					}
					out = append(out, svc)
				}
			}
		}
		if clusters.NextToken == nil {
			return out, nil
		}
		cnext = clusters.NextToken
	}
}
