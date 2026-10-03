// Package apigateway reads Amazon API Gateway APIs as entry points. An API is the front
// door of most serverless code: a route that answers without credentials hands the
// internet whatever sits behind it - a Lambda function, and through it the function's role.
//
//	(internet) API ──ROUTES_TO──▶ Lambda function ──ASSUMES──▶ execution role
//
// An API is an entry point when it is deployed to a stage, is not private, and has a route
// that asks for nothing: no authorizer, no IAM signature, no API key. A REST API's resource
// policy must also let everyone in - and not deny everyone outside a fixed network, which
// an attacker on the internet is outside of. Only the routes that ask for nothing lead
// anywhere; a route behind an authorizer needs a token an attacker does not have, so it
// draws no edge. A custom (Lambda) authorizer counts as asking: what it accepts is code,
// and code is not read.
//
// Input is an API Gateway bundle - per REST API, its endpoint types, policy, stages and
// methods; per HTTP or WebSocket API, its stages, routes and integrations - as the AWS
// connector assembles it, or posted to /ingest/apigateway. Functions are keyed by ARN, as
// the lambda collector keys them, and a private integration's load balancer as the network
// feed keys it, so the route continues into what they lead to.
package apigateway

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type bundle struct {
	Account  string    `json:"account"`
	Region   string    `json:"region"`
	RestAPIs []restAPI `json:"rest_apis"`
	HTTPAPIs []httpAPI `json:"http_apis"`
}

type restAPI struct {
	ID                        string   `json:"id"`
	Name                      string   `json:"name"`
	EndpointTypes             []string `json:"endpointTypes"` // EDGE | REGIONAL | PRIVATE
	DisableExecuteAPIEndpoint bool     `json:"disableExecuteApiEndpoint"`
	Policy                    any      `json:"policy"` // the resource policy, as a document or the string AWS returns
	Stages                    []string `json:"stages"`
	Methods                   []struct {
		Path              string `json:"path"`
		HTTPMethod        string `json:"httpMethod"`
		AuthorizationType string `json:"authorizationType"` // NONE | AWS_IAM | CUSTOM | COGNITO_USER_POOLS
		APIKeyRequired    bool   `json:"apiKeyRequired"`
		IntegrationType   string `json:"integrationType"` // AWS_PROXY | AWS | HTTP | HTTP_PROXY | MOCK
		IntegrationURI    string `json:"integrationUri"`
	} `json:"methods"`
}

type httpAPI struct {
	APIID                     string   `json:"apiId"`
	Name                      string   `json:"name"`
	ProtocolType              string   `json:"protocolType"` // HTTP | WEBSOCKET
	DisableExecuteAPIEndpoint bool     `json:"disableExecuteApiEndpoint"`
	Stages                    []string `json:"stages"`
	Routes                    []struct {
		RouteKey          string `json:"routeKey"`
		AuthorizationType string `json:"authorizationType"` // NONE | JWT | AWS_IAM | CUSTOM
		APIKeyRequired    bool   `json:"apiKeyRequired"`
		Target            string `json:"target"` // integrations/ID
	} `json:"routes"`
	Integrations []struct {
		IntegrationID   string `json:"integrationId"`
		IntegrationType string `json:"integrationType"` // AWS_PROXY | HTTP_PROXY | MOCK…
		IntegrationURI  string `json:"integrationUri"`
		ConnectionType  string `json:"connectionType"` // INTERNET | VPC_LINK
	} `json:"integrations"`
}

// routesProb is an API handing a request on to what serves its route: what it is for.
const routesProb = 0.9

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "apigateway" }

func (c *Collector) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	var b bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, fmt.Errorf("decode apigateway bundle: %w", err)
	}
	account := opts.Account
	if account == "" {
		account = b.Account
	}
	g := graph{nodes: map[string]ontology.Node{}, account: account, region: b.Region}

	for _, api := range b.RestAPIs {
		if api.ID == "" {
			continue
		}
		var open []route
		protected := 0
		for _, m := range api.Methods {
			key := strings.TrimSpace(strings.ToUpper(m.HTTPMethod) + " " + m.Path)
			if !strings.EqualFold(m.AuthorizationType, "NONE") || m.APIKeyRequired {
				protected++
				continue
			}
			open = append(open, route{key: key, target: g.target(m.IntegrationType, m.IntegrationURI, "")})
		}
		gate := ""
		switch {
		case len(api.Stages) == 0:
			gate = "not deployed to any stage"
		case hasFold(api.EndpointTypes, "PRIVATE"):
			gate = "a private API: reachable only through a VPC endpoint"
		case api.Policy != nil:
			policy, err := ingestion.ParseResourcePolicy(api.Policy)
			switch {
			case err != nil:
				// Unreadable: erring toward reporting, the methods decide.
			case !policy.Public("execute-api:Invoke"):
				gate = "its resource policy does not let everyone invoke it"
			case policy.Confined("execute-api:Invoke"):
				gate = "its resource policy denies everyone outside a fixed network"
			}
		}
		g.api(api.ID, api.Name, "rest", api.DisableExecuteAPIEndpoint, gate, open, protected)
	}

	for _, api := range b.HTTPAPIs {
		if api.APIID == "" {
			continue
		}
		integrations := map[string]string{}
		for _, in := range api.Integrations {
			integrations[in.IntegrationID] = g.target(in.IntegrationType, in.IntegrationURI, in.ConnectionType)
		}
		var open []route
		protected := 0
		for _, rt := range api.Routes {
			if !strings.EqualFold(rt.AuthorizationType, "NONE") || rt.APIKeyRequired {
				protected++
				continue
			}
			open = append(open, route{key: rt.RouteKey, target: integrations[strings.TrimPrefix(rt.Target, "integrations/")]})
		}
		gate := ""
		if len(api.Stages) == 0 {
			gate = "not deployed to any stage"
		}
		kind := "http"
		if strings.EqualFold(api.ProtocolType, "WEBSOCKET") {
			kind = "websocket"
		}
		g.api(api.APIID, api.Name, kind, api.DisableExecuteAPIEndpoint, gate, open, protected)
	}

	nodes := make([]ontology.Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      nodes,
		Edges:      g.edges,
	}}, nil
}

// route is one route that asks for nothing, and the node its integration reaches ("" when
// it reaches nothing the graph knows: an HTTP endpoint elsewhere, a mock).
type route struct{ key, target string }

type graph struct {
	nodes           map[string]ontology.Node
	edges           []ontology.Edge
	account, region string
}

// api draws the API node, its verdict, and an edge for each open route that leads somewhere.
func (g *graph) api(id, name, kind string, defaultEndpointOff bool, gate string, open []route, protected int) {
	nodeID := ingestion.RegionalID(ontology.LabelAPI, g.account, g.region, id)
	props := map[string]any{"api_id": id, "api_type": kind}
	if g.account != "" {
		props[ontology.PropAccount] = g.account
	}
	if g.region != "" {
		props["region"] = g.region
		props["endpoint"] = "https://" + id + ".execute-api." + g.region + ".amazonaws.com"
	}
	keys := make([]string, 0, len(open))
	for _, r := range open {
		keys = append(keys, r.key)
	}
	sort.Strings(keys)
	exposed := gate == "" && len(open) > 0
	var how string
	switch {
	case gate != "":
		how = gate
	case len(open) == 0:
		how = "every route asks for credentials"
	default:
		how = fmt.Sprintf("%d of %d routes answer without credentials", len(open), len(open)+protected)
		if defaultEndpointOff {
			how += " (default endpoint disabled: reached through a custom domain, which is not read)"
		}
	}
	// Written either way, so an API whose last open route gains an authorizer, or that is
	// made private, is retracted on the next pull.
	props[ontology.PropNetworkExposed] = exposed
	props["exposure"] = how
	props["open_routes"] = ""
	if exposed {
		props[ontology.PropInternetExposed] = true
		props["open_routes"] = strings.Join(keys, ", ")
	}
	if name == "" {
		name = id
	}
	g.nodes[nodeID] = ontology.Node{ID: nodeID, Label: ontology.LabelAPI, Name: name, Properties: props}
	if !exposed {
		return
	}
	byTarget := map[string][]string{}
	var order []string
	for _, r := range open {
		if r.target == "" {
			continue
		}
		if _, seen := byTarget[r.target]; !seen {
			order = append(order, r.target)
		}
		byTarget[r.target] = append(byTarget[r.target], r.key)
	}
	for _, to := range order {
		sort.Strings(byTarget[to])
		g.edges = append(g.edges, ontology.Edge{Type: ontology.EdgeRoutesTo, From: nodeID, To: to, ExploitProbability: routesProb,
			Properties: map[string]any{"routes": strings.Join(byTarget[to], ", ")}})
	}
}

// functionInURI finds a Lambda function ARN in an integration URI, whether given plainly
// (HTTP APIs) or wrapped in API Gateway's invocation path (REST APIs). A function named
// through a stage variable is not resolved.
var functionInURI = regexp.MustCompile(`arn:aws[a-z-]*:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]+(?::[A-Za-z0-9$_-]+)?`)

// target is the node an integration reaches: a Lambda function, keyed by its plain ARN as
// the lambda collector keys it, or the load balancer behind a private (VPC link)
// integration, keyed as the network feed keys it. Anything else reaches nothing the graph
// knows.
func (g *graph) target(integrationType, uri, connectionType string) string {
	if fn := functionInURI.FindString(uri); fn != "" && strings.HasPrefix(strings.ToUpper(integrationType), "AWS") {
		if parts := strings.Split(fn, ":"); len(parts) > 7 {
			fn = strings.Join(parts[:7], ":")
		}
		g.stub(ontology.NewID(ontology.LabelFunction, fn), ontology.LabelFunction, fn[strings.LastIndex(fn, ":")+1:], fn)
		return ontology.NewID(ontology.LabelFunction, fn)
	}
	if strings.EqualFold(connectionType, "VPC_LINK") && strings.Contains(uri, ":elasticloadbalancing:") {
		lb := ingestion.LoadBalancerARNFromListener(uri)
		name := ingestion.LoadBalancerNameFromARN(lb)
		id := ingestion.LoadBalancerID(g.account, lb, name)
		g.stub(id, ontology.LabelLoadBalancer, name, lb)
		return id
	}
	return ""
}

// stub names a node an edge points at, so the edge has an end even before the feed that
// describes it arrives; the full description merges in when it does.
func (g *graph) stub(id string, label ontology.Label, name, arn string) {
	if _, ok := g.nodes[id]; !ok {
		g.nodes[id] = ontology.Node{ID: id, Label: label, Name: name, Properties: map[string]any{ontology.PropARN: arn}}
	}
}

func hasFold(vals []string, want string) bool {
	for _, v := range vals {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}
