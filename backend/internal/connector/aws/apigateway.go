package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigw "github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

// apigwAPI is the slice of API Gateway (REST APIs) the connector reads: the APIs with their
// endpoint types and resource policies, their resources with each method's authorization
// and integration, and their stages. apigwV2API is the same for HTTP and WebSocket APIs.
// Both are apigateway:GET, inside SecurityAudit.
type apigwAPI interface {
	GetRestApis(context.Context, *apigw.GetRestApisInput, ...func(*apigw.Options)) (*apigw.GetRestApisOutput, error)
	GetResources(context.Context, *apigw.GetResourcesInput, ...func(*apigw.Options)) (*apigw.GetResourcesOutput, error)
	GetStages(context.Context, *apigw.GetStagesInput, ...func(*apigw.Options)) (*apigw.GetStagesOutput, error)
}

type apigwV2API interface {
	GetApis(context.Context, *apigwv2.GetApisInput, ...func(*apigwv2.Options)) (*apigwv2.GetApisOutput, error)
	GetRoutes(context.Context, *apigwv2.GetRoutesInput, ...func(*apigwv2.Options)) (*apigwv2.GetRoutesOutput, error)
	GetIntegrations(context.Context, *apigwv2.GetIntegrationsInput, ...func(*apigwv2.Options)) (*apigwv2.GetIntegrationsOutput, error)
	GetStages(context.Context, *apigwv2.GetStagesInput, ...func(*apigwv2.Options)) (*apigwv2.GetStagesOutput, error)
}

// apiGatewayBundle is the apigateway collector's input. API ARNs carry no account, so the
// bundle names the account and Region it was read in.
type apiGatewayBundle struct {
	Account  string        `json:"account,omitempty"`
	Region   string        `json:"region"`
	RestAPIs []restAPIJSON `json:"rest_apis,omitempty"`
	HTTPAPIs []httpAPIJSON `json:"http_apis,omitempty"`
}

type restAPIJSON struct {
	ID                        string           `json:"id"`
	Name                      string           `json:"name"`
	EndpointTypes             []string         `json:"endpointTypes,omitempty"`
	DisableExecuteAPIEndpoint bool             `json:"disableExecuteApiEndpoint,omitempty"`
	Policy                    string           `json:"policy,omitempty"`
	Stages                    []string         `json:"stages"`
	Methods                   []restMethodJSON `json:"methods"`
}

type restMethodJSON struct {
	Path              string `json:"path"`
	HTTPMethod        string `json:"httpMethod"`
	AuthorizationType string `json:"authorizationType"`
	APIKeyRequired    bool   `json:"apiKeyRequired"`
	IntegrationType   string `json:"integrationType,omitempty"`
	IntegrationURI    string `json:"integrationUri,omitempty"`
}

type httpAPIJSON struct {
	APIID                     string            `json:"apiId"`
	Name                      string            `json:"name"`
	ProtocolType              string            `json:"protocolType"`
	DisableExecuteAPIEndpoint bool              `json:"disableExecuteApiEndpoint,omitempty"`
	Stages                    []string          `json:"stages"`
	Routes                    []httpRouteJSON   `json:"routes"`
	Integrations              []integrationJSON `json:"integrations"`
}

type httpRouteJSON struct {
	RouteKey          string `json:"routeKey"`
	AuthorizationType string `json:"authorizationType"`
	APIKeyRequired    bool   `json:"apiKeyRequired"`
	Target            string `json:"target,omitempty"`
}

type integrationJSON struct {
	IntegrationID   string `json:"integrationId"`
	IntegrationType string `json:"integrationType"`
	IntegrationURI  string `json:"integrationUri,omitempty"`
	ConnectionType  string `json:"connectionType,omitempty"`
}

// fetchAPIGateway reads every REST, HTTP and WebSocket API in the region.
func (t *sdkTransport) fetchAPIGateway(ctx context.Context) ([]byte, error) {
	if t.apigw == nil && t.apigwV2 == nil {
		return nil, nil
	}
	b := apiGatewayBundle{Account: t.Account(ctx), Region: t.region}
	if t.apigw != nil {
		apis, err := t.restAPIs(ctx)
		if err != nil {
			return nil, err
		}
		b.RestAPIs = apis
	}
	if t.apigwV2 != nil {
		apis, err := t.httpAPIs(ctx)
		if err != nil {
			return nil, err
		}
		b.HTTPAPIs = apis
	}
	if len(b.RestAPIs) == 0 && len(b.HTTPAPIs) == 0 {
		return nil, nil
	}
	return json.Marshal(b)
}

func (t *sdkTransport) restAPIs(ctx context.Context) ([]restAPIJSON, error) {
	var out []restAPIJSON
	var pos *string
	for {
		page, err := t.apigw.GetRestApis(ctx, &apigw.GetRestApisInput{Position: pos, Limit: aws.Int32(500)})
		if err != nil {
			return nil, fmt.Errorf("get rest apis: %w", err)
		}
		for _, a := range page.Items {
			api := restAPIJSON{ID: aws.ToString(a.Id), Name: aws.ToString(a.Name), Policy: aws.ToString(a.Policy),
				DisableExecuteAPIEndpoint: a.DisableExecuteApiEndpoint, Stages: []string{}, Methods: []restMethodJSON{}}
			if a.EndpointConfiguration != nil {
				for _, ty := range a.EndpointConfiguration.Types {
					api.EndpointTypes = append(api.EndpointTypes, string(ty))
				}
			}
			stages, err := t.apigw.GetStages(ctx, &apigw.GetStagesInput{RestApiId: a.Id})
			if err != nil {
				return nil, fmt.Errorf("stages of %s: %w", api.Name, err)
			}
			for _, s := range stages.Item {
				api.Stages = append(api.Stages, aws.ToString(s.StageName))
			}
			var rpos *string
			for {
				res, err := t.apigw.GetResources(ctx, &apigw.GetResourcesInput{RestApiId: a.Id, Embed: []string{"methods"}, Position: rpos, Limit: aws.Int32(500)})
				if err != nil {
					return nil, fmt.Errorf("resources of %s: %w", api.Name, err)
				}
				for _, r := range res.Items {
					for verb, m := range r.ResourceMethods {
						method := restMethodJSON{Path: aws.ToString(r.Path), HTTPMethod: first(aws.ToString(m.HttpMethod), verb),
							AuthorizationType: aws.ToString(m.AuthorizationType), APIKeyRequired: aws.ToBool(m.ApiKeyRequired)}
						if in := m.MethodIntegration; in != nil {
							method.IntegrationType, method.IntegrationURI = string(in.Type), aws.ToString(in.Uri)
						}
						api.Methods = append(api.Methods, method)
					}
				}
				if res.Position == nil {
					break
				}
				rpos = res.Position
			}
			out = append(out, api)
		}
		if page.Position == nil {
			return out, nil
		}
		pos = page.Position
	}
}

func (t *sdkTransport) httpAPIs(ctx context.Context) ([]httpAPIJSON, error) {
	var out []httpAPIJSON
	var next *string
	for {
		page, err := t.apigwV2.GetApis(ctx, &apigwv2.GetApisInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("get apis: %w", err)
		}
		for _, a := range page.Items {
			api := httpAPIJSON{APIID: aws.ToString(a.ApiId), Name: aws.ToString(a.Name), ProtocolType: string(a.ProtocolType),
				DisableExecuteAPIEndpoint: aws.ToBool(a.DisableExecuteApiEndpoint), Stages: []string{},
				Routes: []httpRouteJSON{}, Integrations: []integrationJSON{}}
			var tok *string
			for {
				st, err := t.apigwV2.GetStages(ctx, &apigwv2.GetStagesInput{ApiId: a.ApiId, NextToken: tok})
				if err != nil {
					return nil, fmt.Errorf("stages of %s: %w", api.Name, err)
				}
				for _, s := range st.Items {
					api.Stages = append(api.Stages, aws.ToString(s.StageName))
				}
				if st.NextToken == nil {
					break
				}
				tok = st.NextToken
			}
			tok = nil
			for {
				rs, err := t.apigwV2.GetRoutes(ctx, &apigwv2.GetRoutesInput{ApiId: a.ApiId, NextToken: tok})
				if err != nil {
					return nil, fmt.Errorf("routes of %s: %w", api.Name, err)
				}
				for _, r := range rs.Items {
					api.Routes = append(api.Routes, httpRouteJSON{RouteKey: aws.ToString(r.RouteKey), AuthorizationType: string(r.AuthorizationType),
						APIKeyRequired: aws.ToBool(r.ApiKeyRequired), Target: aws.ToString(r.Target)})
				}
				if rs.NextToken == nil {
					break
				}
				tok = rs.NextToken
			}
			tok = nil
			for {
				is, err := t.apigwV2.GetIntegrations(ctx, &apigwv2.GetIntegrationsInput{ApiId: a.ApiId, NextToken: tok})
				if err != nil {
					return nil, fmt.Errorf("integrations of %s: %w", api.Name, err)
				}
				for _, in := range is.Items {
					api.Integrations = append(api.Integrations, integrationJSON{IntegrationID: aws.ToString(in.IntegrationId),
						IntegrationType: string(in.IntegrationType), IntegrationURI: aws.ToString(in.IntegrationUri), ConnectionType: string(in.ConnectionType)})
				}
				if is.NextToken == nil {
					break
				}
				tok = is.NextToken
			}
			out = append(out, api)
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
