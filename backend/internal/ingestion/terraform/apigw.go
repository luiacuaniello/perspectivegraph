package terraform

import (
	"strings"
)

// API Gateway, in the shape the apigateway collector reads: per REST API its endpoint
// types, resource policy, stages and methods with their integrations; per HTTP or
// WebSocket API its stages, routes and integrations. A REST method is named by its
// resource's path, which a plan that creates the resource knows only as the chain of
// path parts up to the API's root.

type apiBundle struct {
	Account  string          `json:"account,omitempty"`
	Region   string          `json:"region,omitempty"`
	RestAPIs []restAPIRecord `json:"rest_apis"`
	HTTPAPIs []httpAPIRecord `json:"http_apis"`
	// described are the APIs the configuration defines, rather than only routes or
	// stages added to them.
	described map[string]bool
}

type restAPIRecord struct {
	ID                        string       `json:"id"`
	Name                      string       `json:"name,omitempty"`
	EndpointTypes             []string     `json:"endpointTypes,omitempty"`
	DisableExecuteAPIEndpoint bool         `json:"disableExecuteApiEndpoint,omitempty"`
	Policy                    any          `json:"policy,omitempty"`
	Stages                    []string     `json:"stages"`
	Methods                   []restMethod `json:"methods"`
}

type restMethod struct {
	Path              string `json:"path"`
	HTTPMethod        string `json:"httpMethod"`
	AuthorizationType string `json:"authorizationType"`
	APIKeyRequired    bool   `json:"apiKeyRequired,omitempty"`
	IntegrationType   string `json:"integrationType,omitempty"`
	IntegrationURI    string `json:"integrationUri,omitempty"`
}

type httpAPIRecord struct {
	APIID                     string            `json:"apiId"`
	Name                      string            `json:"name,omitempty"`
	ProtocolType              string            `json:"protocolType,omitempty"`
	DisableExecuteAPIEndpoint bool              `json:"disableExecuteApiEndpoint,omitempty"`
	Stages                    []string          `json:"stages"`
	Routes                    []httpRoute       `json:"routes"`
	Integrations              []httpIntegration `json:"integrations"`
}

type httpRoute struct {
	RouteKey          string `json:"routeKey"`
	AuthorizationType string `json:"authorizationType"`
	APIKeyRequired    bool   `json:"apiKeyRequired,omitempty"`
	Target            string `json:"target,omitempty"`
}

type httpIntegration struct {
	IntegrationID   string `json:"integrationId"`
	IntegrationType string `json:"integrationType,omitempty"`
	IntegrationURI  string `json:"integrationUri,omitempty"`
	ConnectionType  string `json:"connectionType,omitempty"`
}

func (p *Plan) apis(v View) (apiBundle, []string) {
	b := apiBundle{Account: p.Account, Region: p.Region, RestAPIs: []restAPIRecord{}, HTTPAPIs: []httpAPIRecord{}, described: map[string]bool{}}
	var notes []string

	rest := map[string]*restAPIRecord{}
	var restOrder []string
	staged := map[[2]string]bool{} // (API, stage), REST and HTTP alike
	restAPI := func(id string) *restAPIRecord {
		if a, ok := rest[id]; ok {
			return a
		}
		a := &restAPIRecord{ID: id, Stages: []string{}, Methods: []restMethod{}}
		rest[id] = a
		restOrder = append(restOrder, id)
		return a
	}
	roots := map[string]bool{}
	for _, r := range p.Resources(v, "aws_api_gateway_rest_api") {
		if !r.Managed() {
			continue
		}
		a := restAPI(p.id(v, r))
		a.Name, _ = r.Values["name"].(string)
		a.EndpointTypes = p.Strs(v, r, "endpoint_configuration", 0, "types")
		a.DisableExecuteAPIEndpoint, _ = r.Values["disable_execute_api_endpoint"].(bool)
		if s, _ := r.Values["policy"].(string); s != "" && !unknownAt(r.Unknown, "policy") {
			a.Policy = s
		} else if unknownAt(r.Unknown, "policy") {
			if cfg := p.configOf(r); cfg != nil {
				if _, set := cfg.Expressions["policy"]; set {
					notes = append(notes, r.Address+": its resource policy is known only after apply")
				}
			}
		}
		root, _ := r.Values["root_resource_id"].(string)
		if root == "" {
			root = p.placeholder(v, r, "root_resource_id")
		}
		roots[root] = true
		b.described[a.ID] = true
	}
	for _, r := range p.Resources(v, "aws_api_gateway_rest_api_policy") {
		if !r.Managed() {
			continue
		}
		id := p.Str(v, r, "rest_api_id")
		if id == "" {
			continue
		}
		if s, _ := r.Values["policy"].(string); s != "" && !unknownAt(r.Unknown, "policy") {
			restAPI(id).Policy = s
			continue
		}
		notes = append(notes, r.Address+": the resource policy of API "+id+" is known only after apply")
	}

	type node struct{ parent, part, path string }
	resources := map[string]node{}
	for _, r := range p.Resources(v, "aws_api_gateway_resource") {
		if !r.Managed() {
			continue
		}
		n := node{parent: p.Str(v, r, "parent_id")}
		n.part, _ = r.Values["path_part"].(string)
		if !unknownAt(r.Unknown, "path") {
			n.path, _ = r.Values["path"].(string)
		}
		resources[p.id(v, r)] = n
	}
	var pathOf func(id string, depth int) string
	pathOf = func(id string, depth int) string {
		n, ok := resources[id]
		switch {
		case roots[id] || !ok || depth > maxDepth:
			// The API's root - or a resource the plan does not hold, read as the root.
			return "/"
		case n.path != "":
			return n.path
		}
		return strings.TrimSuffix(pathOf(n.parent, depth+1), "/") + "/" + n.part
	}

	type key struct{ api, resource, method string }
	methods := map[key]*restMethod{}
	var methodOrder []key
	for _, r := range p.Resources(v, "aws_api_gateway_method") {
		if !r.Managed() {
			continue
		}
		k := key{p.Str(v, r, "rest_api_id"), p.Str(v, r, "resource_id"), strings.ToUpper(p.Str(v, r, "http_method"))}
		if k.api == "" {
			notes = append(notes, r.Address+": the API it belongs to is known only after apply")
			continue
		}
		m := &restMethod{Path: pathOf(k.resource, 0), HTTPMethod: k.method, AuthorizationType: strings.ToUpper(p.Str(v, r, "authorization"))}
		if m.AuthorizationType == "" {
			m.AuthorizationType = "NONE"
		}
		m.APIKeyRequired, _ = r.Values["api_key_required"].(bool)
		methods[k] = m
		methodOrder = append(methodOrder, k)
	}
	for _, r := range p.Resources(v, "aws_api_gateway_integration") {
		if !r.Managed() {
			continue
		}
		k := key{p.Str(v, r, "rest_api_id"), p.Str(v, r, "resource_id"), strings.ToUpper(p.Str(v, r, "http_method"))}
		if m, ok := methods[k]; ok {
			m.IntegrationType = strings.ToUpper(p.Str(v, r, "type"))
			m.IntegrationURI = p.Str(v, r, "uri")
		}
	}
	for _, k := range methodOrder {
		a := restAPI(k.api)
		a.Methods = append(a.Methods, *methods[k])
	}
	for _, r := range p.Resources(v, "aws_api_gateway_stage", "aws_api_gateway_deployment") {
		if !r.Managed() {
			continue
		}
		if id, stage := p.Str(v, r, "rest_api_id"), p.Str(v, r, "stage_name"); id != "" && stage != "" && !staged[[2]string{id, stage}] {
			staged[[2]string{id, stage}] = true
			a := restAPI(id)
			a.Stages = append(a.Stages, stage)
		}
	}

	httpAPIs := map[string]*httpAPIRecord{}
	var httpOrder []string
	httpAPI := func(id string) *httpAPIRecord {
		if a, ok := httpAPIs[id]; ok {
			return a
		}
		a := &httpAPIRecord{APIID: id, Stages: []string{}, Routes: []httpRoute{}, Integrations: []httpIntegration{}}
		httpAPIs[id] = a
		httpOrder = append(httpOrder, id)
		return a
	}
	for _, r := range p.Resources(v, "aws_apigatewayv2_api") {
		if !r.Managed() {
			continue
		}
		a := httpAPI(p.id(v, r))
		a.Name, _ = r.Values["name"].(string)
		a.ProtocolType, _ = r.Values["protocol_type"].(string)
		a.DisableExecuteAPIEndpoint, _ = r.Values["disable_execute_api_endpoint"].(bool)
		b.described[a.APIID] = true
		// Quick create: a target on the API itself is a default route, integration and
		// stage, created with it and asking for nothing.
		if t := p.Str(v, r, "target"); t != "" {
			typ := "HTTP_PROXY"
			if strings.Contains(t, ":lambda:") {
				typ = "AWS_PROXY"
			}
			routeKey, _ := r.Values["route_key"].(string)
			if routeKey == "" {
				routeKey = "$default"
			}
			a.Integrations = append(a.Integrations, httpIntegration{IntegrationID: "quick-create", IntegrationType: typ, IntegrationURI: t})
			a.Routes = append(a.Routes, httpRoute{RouteKey: routeKey, AuthorizationType: "NONE", Target: "integrations/quick-create"})
			a.Stages = append(a.Stages, "$default")
			staged[[2]string{a.APIID, "$default"}] = true
		}
	}
	for _, r := range p.Resources(v, "aws_apigatewayv2_integration") {
		if !r.Managed() {
			continue
		}
		id := p.Str(v, r, "api_id")
		if id == "" {
			continue
		}
		in := httpIntegration{IntegrationID: p.id(v, r), IntegrationType: strings.ToUpper(p.Str(v, r, "integration_type")),
			IntegrationURI: p.Str(v, r, "integration_uri"), ConnectionType: strings.ToUpper(p.Str(v, r, "connection_type"))}
		a := httpAPI(id)
		a.Integrations = append(a.Integrations, in)
	}
	for _, r := range p.Resources(v, "aws_apigatewayv2_route") {
		if !r.Managed() {
			continue
		}
		id := p.Str(v, r, "api_id")
		if id == "" {
			notes = append(notes, r.Address+": the API it belongs to is known only after apply")
			continue
		}
		rt := httpRoute{RouteKey: p.Str(v, r, "route_key"), AuthorizationType: strings.ToUpper(p.Str(v, r, "authorization_type")), Target: p.routeTarget(v, r)}
		if rt.AuthorizationType == "" {
			rt.AuthorizationType = "NONE"
		}
		rt.APIKeyRequired, _ = r.Values["api_key_required"].(bool)
		a := httpAPI(id)
		a.Routes = append(a.Routes, rt)
	}
	for _, r := range p.Resources(v, "aws_apigatewayv2_stage") {
		if !r.Managed() {
			continue
		}
		if id, name := p.Str(v, r, "api_id"), p.Str(v, r, "name"); id != "" && name != "" && !staged[[2]string{id, name}] {
			staged[[2]string{id, name}] = true
			a := httpAPI(id)
			a.Stages = append(a.Stages, name)
		}
	}

	for _, id := range restOrder {
		b.RestAPIs = append(b.RestAPIs, *rest[id])
	}
	for _, id := range httpOrder {
		b.HTTPAPIs = append(b.HTTPAPIs, *httpAPIs[id])
	}
	return b, notes
}

// routeTarget is a route's integration, integrations/<id>. A configuration writes it as
// a template around the integration's id, which a plan that creates the integration
// leaves unknown: the template's reference names the integration.
func (p *Plan) routeTarget(v View, r *Resource) string {
	if s, _ := r.Values["target"].(string); s != "" && !unknownAt(r.Unknown, "target") {
		return s
	}
	cfg := p.configOf(r)
	if cfg == nil {
		return ""
	}
	refs, ok := exprRefs(cfg.Expressions, "target")
	if !ok {
		return ""
	}
	var integrations []string
	for _, ref := range refs {
		if strings.HasPrefix(ref, "aws_apigatewayv2_integration.") {
			integrations = append(integrations, ref)
		}
	}
	for _, x := range p.resolve(v, r.Module, integrations, 0) {
		if id, _ := x.(string); id != "" {
			return "integrations/" + id
		}
	}
	return ""
}
