package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigw "github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	apigwv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/apigateway"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// fakeAPIGW has one REST API deployed to prod: GET /orders asks for nothing and invokes a
// function, POST /orders asks for an IAM signature.
type fakeAPIGW struct{}

func (fakeAPIGW) GetRestApis(context.Context, *apigw.GetRestApisInput, ...func(*apigw.Options)) (*apigw.GetRestApisOutput, error) {
	return &apigw.GetRestApisOutput{Items: []apigwtypes.RestApi{{Id: aws.String("r1"), Name: aws.String("orders"),
		EndpointConfiguration: &apigwtypes.EndpointConfiguration{Types: []apigwtypes.EndpointType{apigwtypes.EndpointTypeRegional}}}}}, nil
}

func (fakeAPIGW) GetResources(context.Context, *apigw.GetResourcesInput, ...func(*apigw.Options)) (*apigw.GetResourcesOutput, error) {
	integration := &apigwtypes.Integration{Type: apigwtypes.IntegrationTypeAwsProxy,
		Uri: aws.String("arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/" + fnArn + "orders/invocations")}
	return &apigw.GetResourcesOutput{Items: []apigwtypes.Resource{{Path: aws.String("/orders"), ResourceMethods: map[string]apigwtypes.Method{
		"GET":  {HttpMethod: aws.String("GET"), AuthorizationType: aws.String("NONE"), ApiKeyRequired: aws.Bool(false), MethodIntegration: integration},
		"POST": {HttpMethod: aws.String("POST"), AuthorizationType: aws.String("AWS_IAM"), MethodIntegration: integration},
	}}}}, nil
}

func (fakeAPIGW) GetStages(context.Context, *apigw.GetStagesInput, ...func(*apigw.Options)) (*apigw.GetStagesOutput, error) {
	return &apigw.GetStagesOutput{Item: []apigwtypes.Stage{{StageName: aws.String("prod")}}}, nil
}

// fakeAPIGWv2 has one HTTP API: GET /items asks for nothing, POST /items wants a JWT.
type fakeAPIGWv2 struct{}

func (fakeAPIGWv2) GetApis(context.Context, *apigwv2.GetApisInput, ...func(*apigwv2.Options)) (*apigwv2.GetApisOutput, error) {
	return &apigwv2.GetApisOutput{Items: []apigwv2types.Api{{ApiId: aws.String("h1"), Name: aws.String("shop"), ProtocolType: apigwv2types.ProtocolTypeHttp}}}, nil
}

func (fakeAPIGWv2) GetRoutes(context.Context, *apigwv2.GetRoutesInput, ...func(*apigwv2.Options)) (*apigwv2.GetRoutesOutput, error) {
	return &apigwv2.GetRoutesOutput{Items: []apigwv2types.Route{
		{RouteKey: aws.String("GET /items"), AuthorizationType: apigwv2types.AuthorizationTypeNone, Target: aws.String("integrations/i1")},
		{RouteKey: aws.String("POST /items"), AuthorizationType: apigwv2types.AuthorizationTypeJwt, Target: aws.String("integrations/i2")},
	}}, nil
}

func (fakeAPIGWv2) GetIntegrations(context.Context, *apigwv2.GetIntegrationsInput, ...func(*apigwv2.Options)) (*apigwv2.GetIntegrationsOutput, error) {
	return &apigwv2.GetIntegrationsOutput{Items: []apigwv2types.Integration{
		{IntegrationId: aws.String("i1"), IntegrationType: apigwv2types.IntegrationTypeAwsProxy, IntegrationUri: aws.String(fnArn + "items")},
		{IntegrationId: aws.String("i2"), IntegrationType: apigwv2types.IntegrationTypeAwsProxy, IntegrationUri: aws.String(fnArn + "items-write")},
	}}, nil
}

func (fakeAPIGWv2) GetStages(context.Context, *apigwv2.GetStagesInput, ...func(*apigwv2.Options)) (*apigwv2.GetStagesOutput, error) {
	return &apigwv2.GetStagesOutput{Items: []apigwv2types.Stage{{StageName: aws.String("$default")}}}, nil
}

// The connector reads both kinds of API with their stages, routes' authorization and
// integrations, and the collector turns the open routes into routes into the functions.
func TestSDKReadsAPIGateway(t *testing.T) {
	tr := &sdkTransport{apigw: fakeAPIGW{}, apigwV2: fakeAPIGWv2{}, region: "eu-west-1"}
	raw, err := tr.Fetch(context.Background(), FeedAPIGateway)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	events, err := apigateway.New().Parse(strings.NewReader(string(raw)), ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	apis := map[string]ontology.Node{}
	for _, n := range events[0].Nodes {
		if n.Label == ontology.LabelAPI {
			apis[n.Name] = n
		}
	}
	for name, open := range map[string]string{"orders": "GET /orders", "shop": "GET /items"} {
		if n := apis[name]; !n.InternetExposed() || n.Properties["open_routes"] != open {
			t.Errorf("%s: exposed=%v open=%v, want %q", name, n.InternetExposed(), n.Properties["open_routes"], open)
		}
	}
	reached := map[string]bool{}
	for _, e := range events[0].Edges {
		reached[e.To] = true
	}
	for _, f := range []string{"orders", "items"} {
		if !reached[ontology.NewID(ontology.LabelFunction, fnArn+f)] {
			t.Errorf("an open route reaches %s", f)
		}
	}
	if reached[ontology.NewID(ontology.LabelFunction, fnArn+"items-write")] {
		t.Error("a route behind a JWT authorizer reaches nothing")
	}
}
