package ingestion

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ResourcePolicy is a resource-based policy - an S3 bucket policy, a Lambda function
// policy: who it lets do what to the resource it is attached to. Only what decides access
// from outside is read: the effect, the principals, the actions and whether a condition
// narrows who.
type ResourcePolicy struct {
	Statements []ResourceStatement
}

// ResourceStatement is one statement of a resource policy.
type ResourceStatement struct {
	Allow bool
	// Principals are the AWS principals it names: "*" for anyone, ARNs, account ids.
	Principals []string
	// Services are the AWS services it names (apigateway.amazonaws.com…).
	Services []string
	Actions  []string
	// Narrowed means a condition limits who the statement applies to - a source IP or
	// VPC endpoint, an organization, a source account or ARN. A condition only on the
	// transport or on a Lambda function URL's auth type narrows nothing: it lets anyone in
	// who asks the right way.
	Narrowed bool
}

// conditionKeysThatNarrowNothing are condition keys that leave a statement open to anyone.
var conditionKeysThatNarrowNothing = map[string]bool{
	"aws:securetransport":        true,
	"lambda:functionurlauthtype": true,
}

// ParseResourcePolicy reads a policy given as a JSON document or as the string the AWS
// APIs return it in. An empty policy is no policy.
func ParseResourcePolicy(raw any) (ResourcePolicy, error) {
	var doc []byte
	switch v := raw.(type) {
	case nil:
		return ResourcePolicy{}, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return ResourcePolicy{}, nil
		}
		doc = []byte(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ResourcePolicy{}, err
		}
		doc = b
	}
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(doc, &p); err != nil {
		return ResourcePolicy{}, fmt.Errorf("decode resource policy: %w", err)
	}
	var stmts []map[string]any
	if len(p.Statement) > 0 && p.Statement[0] == '{' {
		var one map[string]any
		if err := json.Unmarshal(p.Statement, &one); err != nil {
			return ResourcePolicy{}, fmt.Errorf("decode resource policy statement: %w", err)
		}
		stmts = []map[string]any{one}
	} else if len(p.Statement) > 0 {
		if err := json.Unmarshal(p.Statement, &stmts); err != nil {
			return ResourcePolicy{}, fmt.Errorf("decode resource policy statements: %w", err)
		}
	}
	var out ResourcePolicy
	for _, st := range stmts {
		s := ResourceStatement{
			Allow:   strings.EqualFold(fmt.Sprint(st["Effect"]), "Allow"),
			Actions: strs(st["Action"]),
		}
		switch pr := st["Principal"].(type) {
		case string:
			s.Principals = []string{pr}
		case map[string]any:
			s.Principals = strs(pr["AWS"])
			s.Services = strs(pr["Service"])
		}
		if cond, ok := st["Condition"].(map[string]any); ok {
			for _, block := range cond {
				keys, _ := block.(map[string]any)
				for k := range keys {
					if !conditionKeysThatNarrowNothing[strings.ToLower(k)] {
						s.Narrowed = true
					}
				}
			}
		}
		out.Statements = append(out.Statements, s)
	}
	return out, nil
}

// Public reports whether the policy lets anyone perform one of the actions: an Allow
// naming every principal, not narrowed by a condition, and no unconditional Deny of every
// principal over that action.
func (p ResourcePolicy) Public(actions ...string) bool {
	allowed := false
	for _, s := range p.Statements {
		if !s.anyone() || !s.covers(actions) || s.Narrowed {
			continue
		}
		if !s.Allow {
			return false
		}
		allowed = true
	}
	return allowed
}

// Grantees are the IAM roles and users an Allow names for one of the actions - access a
// resource hands to principals, often in other accounts, that their own policies need not
// mention.
func (p ResourcePolicy) Grantees(actions ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range p.Statements {
		if !s.Allow || !s.covers(actions) {
			continue
		}
		for _, pr := range s.Principals {
			if (strings.Contains(pr, ":role/") || strings.Contains(pr, ":user/")) && !seen[pr] {
				seen[pr] = true
				out = append(out, pr)
			}
		}
	}
	return out
}

func (s ResourceStatement) anyone() bool {
	for _, pr := range s.Principals {
		if pr == "*" {
			return true
		}
	}
	return false
}

func (s ResourceStatement) covers(actions []string) bool {
	for _, pattern := range s.Actions {
		for _, a := range actions {
			if globMatch(strings.ToLower(pattern), strings.ToLower(a)) {
				return true
			}
		}
	}
	return false
}

// globMatch matches an IAM action pattern, where '*' stands for any run of characters.
func globMatch(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i, part := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(s, part)
		}
		idx := strings.Index(s, part)
		if idx < 0 {
			return false
		}
		s = s[idx+len(part):]
	}
	return true
}

// strs reads a string-or-list JSON value.
func strs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
