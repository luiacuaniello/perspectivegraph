package apigateway

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const (
	acct = "123456789012"
	fn   = "arn:aws:lambda:eu-west-1:" + acct + ":function:"
	inv  = "arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/" + fn
)

// An API is an entry point when it is deployed, not private, lets everyone in, and has a
// route that asks for nothing; only those routes lead anywhere.
func TestAnAPIRouteWithoutCredentialsIsAnEntryPoint(t *testing.T) {
	method := func(verb, path, auth string, key bool, target string) string {
		k := "false"
		if key {
			k = "true"
		}
		return `{"path":"` + path + `","httpMethod":"` + verb + `","authorizationType":"` + auth + `","apiKeyRequired":` + k +
			`,"integrationType":"AWS_PROXY","integrationUri":"` + inv + target + `/invocations"}`
	}
	rest := func(id, types, stages, policy string, methods ...string) string {
		s := `{"id":"` + id + `","name":"` + id + `","endpointTypes":[` + types + `],"stages":[` + stages + `],"methods":[` + strings.Join(methods, ",") + `]`
		if policy != "" {
			s += `,"policy":` + policy
		}
		return s + `}`
	}
	allowAll := `{"Effect":"Allow","Principal":"*","Action":"execute-api:Invoke","Resource":"*"}`
	// As GetRestApis hands it back: a string whose quotes and slashes are escaped.
	officeOnly := `"{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:eu-west-1:` + acct + `:office\\\/*\\\"},{\\\"Effect\\\":\\\"Deny\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:eu-west-1:` + acct + `:office\\\/*\\\",\\\"Condition\\\":{\\\"NotIpAddress\\\":{\\\"aws:SourceIp\\\":\\\"203.0.113.0\\\/24\\\"}}}]}"`
	partner := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"execute-api:Invoke","Resource":"*"}]}`
	bundle := `{"account":"` + acct + `","region":"eu-west-1","rest_apis":[` + strings.Join([]string{
		rest("orders", `"REGIONAL"`, `"prod"`, "",
			method("GET", "/orders", "NONE", false, "orders:live"),
			method("POST", "/orders", "AWS_IAM", false, "orders-write"),
			method("GET", "/admin", "NONE", true, "admin")),
		rest("internal", `"PRIVATE"`, `"prod"`, "", method("GET", "/", "NONE", false, "internal")),
		rest("draft", `"REGIONAL"`, ``, "", method("GET", "/", "NONE", false, "draft")),
		rest("office", `"REGIONAL"`, `"prod"`, officeOnly, method("GET", "/", "NONE", false, "office")),
		rest("partner", `"REGIONAL"`, `"prod"`, partner, method("GET", "/", "NONE", false, "partner")),
		rest("published", `"EDGE"`, `"prod"`, `{"Statement":[`+allowAll+`]}`, method("GET", "/", "NONE", false, "published")),
		rest("authorized", `"REGIONAL"`, `"prod"`, "", method("GET", "/", "CUSTOM", false, "authorized"), method("PUT", "/", "COGNITO_USER_POOLS", false, "authorized")),
	}, ",") + `],"http_apis":[
	  {"apiId":"shop","name":"shop","protocolType":"HTTP","stages":["$default"],
	   "routes":[{"routeKey":"GET /items","authorizationType":"NONE","target":"integrations/i1"},
	             {"routeKey":"POST /items","authorizationType":"JWT","target":"integrations/i2"},
	             {"routeKey":"$default","authorizationType":"NONE","target":"integrations/i3"}],
	   "integrations":[{"integrationId":"i1","integrationType":"AWS_PROXY","integrationUri":"` + fn + `items"},
	                   {"integrationId":"i2","integrationType":"AWS_PROXY","integrationUri":"` + fn + `items-write"},
	                   {"integrationId":"i3","integrationType":"HTTP_PROXY","connectionType":"VPC_LINK",
	                    "integrationUri":"arn:aws:elasticloadbalancing:eu-west-1:` + acct + `:listener/app/internal-web/50dc6c49/4b9e1c2d"}]},
	  {"apiId":"later","name":"later","protocolType":"HTTP","stages":[],
	   "routes":[{"routeKey":"GET /","authorizationType":"NONE","target":"integrations/i9"}],
	   "integrations":[{"integrationId":"i9","integrationType":"AWS_PROXY","integrationUri":"` + fn + `later"}]}
	]}`
	events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	apis := map[string]ontology.Node{}
	for _, n := range events[0].Nodes {
		if n.Label == ontology.LabelAPI {
			apis[n.Name] = n
		}
	}
	for name, want := range map[string]string{
		"orders": "GET /orders", "shop": "$default, GET /items", "published": "GET /",
		"internal": "", "draft": "", "office": "", "partner": "", "authorized": "", "later": "",
	} {
		n, ok := apis[name]
		if !ok {
			t.Fatalf("API %s not drawn", name)
		}
		v, written := n.Properties[ontology.PropNetworkExposed]
		if !written || v != (want != "") || n.Properties["open_routes"] != want {
			t.Errorf("%s: exposed=%v (written=%v) open=%q, want %q (%v)", name, v, written, n.Properties["open_routes"], want, n.Properties["exposure"])
		}
	}
	if want := ingestion.RegionalID(ontology.LabelAPI, acct, "eu-west-1", "orders"); apis["orders"].ID != want {
		t.Errorf("an API is keyed by account, Region and id: got %s", apis["orders"].ID)
	}
	edges := map[string]string{}
	for _, e := range events[0].Edges {
		edges[e.From+">"+e.To] = e.Properties["routes"].(string)
	}
	fnID := func(name string) string { return ontology.NewID(ontology.LabelFunction, fn+name) }
	for _, want := range []struct{ from, to, routes string }{
		{apis["orders"].ID, fnID("orders"), "GET /orders"}, // the alias falls away: one function
		{apis["shop"].ID, fnID("items"), "GET /items"},
		{apis["shop"].ID, ingestion.RegionalID(ontology.LabelLoadBalancer, acct, "eu-west-1", "internal-web"), "$default"},
		{apis["published"].ID, fnID("published"), "GET /"},
	} {
		if got, ok := edges[want.from+">"+want.to]; !ok || got != want.routes {
			t.Errorf("missing route %s -> %s on %q (got %q, present=%v)", want.from, want.to, want.routes, got, ok)
		}
	}
	if len(edges) != 4 {
		t.Errorf("edges = %v: only open routes of open APIs lead anywhere", edges)
	}
}
