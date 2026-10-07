package terraform

import (
	"strings"
	"time"
)

// The Lambda feed, in the shape the lambda collector reads: per function, its execution
// role, its URL and its resource policy - here built from the aws_lambda_permission
// resources the way Lambda builds the policy from AddPermission calls.

type lambdaBundle struct {
	Functions []lambdaFunction `json:"functions"`
}

type lambdaFunction struct {
	FunctionName string            `json:"FunctionName"`
	FunctionArn  string            `json:"FunctionArn"`
	Role         string            `json:"Role,omitempty"`
	URL          *functionURL      `json:"Url,omitempty"`
	Policy       any               `json:"Policy,omitempty"`
	Tags         map[string]string `json:"Tags,omitempty"`
}

type functionURL struct {
	AuthType     string `json:"AuthType"`
	FunctionURL  string `json:"FunctionUrl"`
	CreationTime string `json:"CreationTime,omitempty"`
}

func (p *Plan) lambda(v View) (lambdaBundle, []string) {
	b := lambdaBundle{Functions: []lambdaFunction{}}
	var notes []string
	fns := map[string]*lambdaFunction{} // by name
	var order []string
	statements := map[string][]any{}

	// A function is named by name or by ARN, with or without a version; the name is what
	// ties a URL and a permission to it.
	nameOf := func(s string) string {
		if strings.HasPrefix(s, "arn:") {
			parts := strings.Split(s, ":")
			if len(parts) >= 7 {
				return parts[6]
			}
		}
		return s
	}
	for _, r := range p.Resources(v, "aws_lambda_function") {
		if !r.Managed() {
			continue
		}
		name := p.nameOf(v, r)
		f := &lambdaFunction{FunctionName: name, FunctionArn: p.arnOf(v, r)}
		f.Role = p.Str(v, r, "role")
		if f.Role == "" {
			notes = append(notes, r.Address+": its execution role is known only after apply")
		}
		if tags, ok := r.Values["tags"].(map[string]any); ok {
			f.Tags = map[string]string{}
			for k, x := range tags {
				f.Tags[k], _ = x.(string)
			}
		}
		fns[name] = f
		order = append(order, name)
		// A function the configuration defines has the permissions it defines: Lambda
		// adds none of its own when a URL is created through the API, as Terraform does.
		statements[name] = []any{}
	}
	function := func(name string) *lambdaFunction {
		if f, ok := fns[name]; ok {
			return f
		}
		region := p.Region
		f := &lambdaFunction{FunctionName: name, FunctionArn: "arn:aws:lambda:" + region + ":" + p.accountOr() + ":function:" + name}
		fns[name] = f
		order = append(order, name)
		return f
	}
	for _, r := range p.Resources(v, "aws_lambda_function_url") {
		if !r.Managed() {
			continue
		}
		name := nameOf(p.Str(v, r, "function_name"))
		if name == "" {
			continue
		}
		f := function(name)
		u := &functionURL{AuthType: p.Str(v, r, "authorization_type"), FunctionURL: p.Str(v, r, "function_url")}
		if u.FunctionURL == "" {
			u.FunctionURL = placeholderAddress
		}
		// Only a URL created by this plan has a known creation time - now - and so falls
		// under the rule for URLs created since October 2025. Of an existing one the state
		// records none, and the lambda collector holds it to the older rule.
		if v == Planned && contains(r.Actions, "create") {
			t := p.Timestamp
			if t.IsZero() {
				t = time.Now().UTC()
			}
			u.CreationTime = t.Format(time.RFC3339Nano)
		}
		f.URL = u
	}
	for _, r := range p.Resources(v, "aws_lambda_permission") {
		if !r.Managed() {
			continue
		}
		name := nameOf(p.Str(v, r, "function_name"))
		if name == "" {
			notes = append(notes, r.Address+": the function it opens is known only after apply")
			continue
		}
		f := function(name)
		principal := p.Str(v, r, "principal")
		if principal == "" {
			notes = append(notes, r.Address+": whom it lets in is known only after apply")
			continue
		}
		stmt := map[string]any{
			"Sid":       p.Str(v, r, "statement_id"),
			"Effect":    "Allow",
			"Principal": principalOf(principal),
			"Action":    p.Str(v, r, "action"),
			"Resource":  f.FunctionArn,
		}
		cond := map[string]map[string]any{}
		set := func(op, key, val string) {
			if val == "" {
				return
			}
			if cond[op] == nil {
				cond[op] = map[string]any{}
			}
			cond[op][key] = val
		}
		set("ArnLike", "AWS:SourceArn", p.Str(v, r, "source_arn"))
		set("StringEquals", "AWS:SourceAccount", p.Str(v, r, "source_account"))
		set("StringEquals", "lambda:FunctionUrlAuthType", p.Str(v, r, "function_url_auth_type"))
		set("StringEquals", "aws:PrincipalOrgID", p.Str(v, r, "principal_org_id"))
		if via, _ := r.Values["invoked_via_function_url"].(bool); via {
			set("Bool", "lambda:InvokedViaFunctionUrl", "true")
		}
		if len(cond) > 0 {
			stmt["Condition"] = cond
		}
		statements[name] = append(statements[name], stmt)
	}
	for _, name := range order {
		f := fns[name]
		if st, ok := statements[name]; ok {
			f.Policy = map[string]any{"Version": "2012-10-17", "Statement": st}
		}
		b.Functions = append(b.Functions, *f)
	}
	return b, notes
}

// principalOf writes a permission's principal the way Lambda writes it into the policy:
// "*" as it is, a service by its domain, an account or role as AWS.
func principalOf(s string) any {
	switch {
	case s == "*":
		return "*"
	case strings.HasSuffix(s, ".amazonaws.com") || strings.HasSuffix(s, ".amazonaws.com.cn"):
		return map[string]any{"Service": s}
	}
	return map[string]any{"AWS": s}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
