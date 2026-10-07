// Package lambda reads AWS Lambda functions as entry points and as identities. A function
// runs code with an execution role, and its credentials sit in its environment: whoever
// runs code in the function holds the role. A function is an entry point when anyone can
// invoke it - a function URL without authentication, or a resource policy that lets every
// principal invoke it.
//
//	(internet) Function ──ASSUMES──▶ execution role
//
// Input is a Lambda bundle - per function, what `aws lambda list-functions`,
// `get-function-url-config`, `get-policy` and `list-tags` return - as the AWS connector
// assembles it, or posted to /ingest/lambda. Roles are keyed by ARN, as the iam collector
// keys them, so a function's route continues into its role's escalations. A function an
// API invokes is marked here; whether the API asks for credentials is read by the
// apigateway collector, which draws the route from the API to the function.
package lambda

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type bundle struct {
	Functions []struct {
		FunctionName string            `json:"FunctionName"`
		FunctionArn  string            `json:"FunctionArn"`
		Role         string            `json:"Role"`
		URL          *functionURL      `json:"Url"`
		Policy       any               `json:"Policy"` // the policy document, or the string get-policy returns
		Tags         map[string]string `json:"Tags"`
	} `json:"functions"`
}

// functionURL is a function's URL configuration, as get-function-url-config returns it.
type functionURL struct {
	AuthType     string `json:"AuthType"` // NONE | AWS_IAM
	FunctionURL  string `json:"FunctionUrl"`
	CreationTime string `json:"CreationTime"`
}

// invokeGrantSince is when function URLs began needing lambda:InvokeFunction on top of
// lambda:InvokeFunctionUrl: Lambda applies it to URLs created from October 2025, and a URL
// without both answers 403 even with AuthType NONE. A URL created before November 2025, or
// one whose creation time the input does not carry, is held to the older rule - the URL
// grant alone - erring toward reporting.
var invokeGrantSince = time.Date(2025, time.November, 1, 0, 0, 0, 0, time.UTC)

// needsInvokeGrant reports whether the URL is new enough to need both grants.
func (u *functionURL) needsInvokeGrant() bool {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700"} {
		if t, err := time.Parse(layout, u.CreationTime); err == nil {
			return !t.Before(invokeGrantSince)
		}
	}
	return false
}

// roleProb is code running in the function becoming its role: the credentials are in the
// function's environment, no call needed.
const roleProb = 0.9

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "lambda" }

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	var b bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, fmt.Errorf("decode lambda bundle: %w", err)
	}
	nodes := map[string]ontology.Node{}
	var edges []ontology.Edge
	for _, f := range b.Functions {
		if f.FunctionArn == "" {
			continue
		}
		props := map[string]any{ontology.PropARN: f.FunctionArn}
		if acct := ingestion.AccountFromARN(f.FunctionArn); acct != "" {
			props[ontology.PropAccount] = acct
		}
		if region := ingestion.RegionFromARN(f.FunctionArn); region != "" {
			props["region"] = region
		}
		policy, err := ingestion.ParseResourcePolicy(f.Policy)
		if err != nil {
			props["policy_note"] = "function policy not read: " + err.Error()
		}
		exposed, how := exposure(f.URL, f.Policy != nil && err == nil, policy)
		// Written either way, as the network source writes its verdict: removing a public
		// function URL must take the function off the internet on the next pull.
		props[ontology.PropNetworkExposed] = exposed
		props[ontology.PropExposure] = how
		if exposed {
			props[ontology.PropInternetExposed] = true
		}
		if f.URL != nil && f.URL.FunctionURL != "" {
			props["function_url"] = f.URL.FunctionURL
		}
		for _, s := range policy.Statements {
			for _, svc := range s.Services {
				if s.Allow && svc == "apigateway.amazonaws.com" {
					props["invoked_by"] = "API Gateway (the apigateway feed decides whether that is a way in)"
				}
			}
		}
		ingestion.MarkCrownJewelFromTags(props, f.Tags)
		name := f.FunctionName
		if name == "" {
			name = f.FunctionArn[strings.LastIndex(f.FunctionArn, ":")+1:]
		}
		id := ontology.NewID(ontology.LabelFunction, f.FunctionArn)
		nodes[id] = ontology.Node{ID: id, Label: ontology.LabelFunction, Name: name, Properties: props}

		if f.Role != "" {
			role := ontology.NewID(ontology.LabelIAMRole, f.Role)
			if _, ok := nodes[role]; !ok {
				nodes[role] = ontology.Node{ID: role, Label: ontology.LabelIAMRole, Name: f.Role[strings.LastIndex(f.Role, "/")+1:],
					Properties: map[string]any{ontology.PropARN: f.Role}}
			}
			edges = append(edges, ontology.Edge{Type: ontology.EdgeAssumes, From: id, To: role, ExploitProbability: roleProb})
		}
	}
	out := make([]ontology.Node, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n)
	}
	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      out,
		Edges:      edges,
	}}, nil
}

// exposure decides whether anyone can invoke the function, and says how. A function URL
// with AuthType NONE still needs the function policy to let every principal through it:
// lambda:InvokeFunctionUrl, and for a URL created since October 2025 lambda:InvokeFunction
// as well - without it Lambda answers 403, which scripts/entrypoints-lab-aws.sh observed on a
// real account. When the policy is not in the input, the URL alone is taken as the answer,
// erring toward reporting. A policy letting every principal call the function directly
// opens it to anyone with an AWS account, which an attacker has.
func exposure(url *functionURL, policyKnown bool, policy ingestion.ResourcePolicy) (bool, string) {
	direct := policy.Public("lambda:InvokeFunction")
	if url != nil && strings.EqualFold(url.AuthType, "NONE") {
		switch {
		case !policyKnown:
			return true, ontology.ExposureFunctionURL
		case !policy.PublicThroughURL("NONE", "lambda:InvokeFunctionUrl"):
			if !direct {
				return false, "function URL without authentication, but the function policy lets no one invoke it"
			}
		case !url.needsInvokeGrant() || policy.PublicThroughURL("NONE", "lambda:InvokeFunction"):
			return true, ontology.ExposureFunctionURL
		case !direct:
			return false, "function URL without authentication, but its policy lacks the lambda:InvokeFunction grant a URL created since October 2025 also needs"
		}
	}
	if direct {
		return true, ontology.ExposureFunctionPolicy
	}
	return false, "invocable only by principals it names"
}
