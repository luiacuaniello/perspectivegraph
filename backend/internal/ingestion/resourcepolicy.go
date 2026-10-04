package ingestion

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ResourcePolicy is a resource-based policy - an S3 bucket policy, a Lambda function
// policy: who it lets do what to the resource it is attached to. Only what decides access
// from outside is read: the effect, the principals, the actions and whether a condition
// narrows who.
//
// What counts as public is AWS's definition, the one S3 Block Public Access applies and
// GetBucketPolicyStatus reports: a statement open to every principal is public unless a
// condition confines it to fixed values of a short list of keys - who the caller is, the
// network it comes from, the resource calling. Any other condition, a Referer or a user
// agent, is one a stranger can meet. Checked against GetBucketPolicyStatus on a real
// account by scripts/entrypoints-lab-aws.sh.
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
	// Narrowed means a condition confines the statement to callers AWS does not count as
	// the public: fixed values of one of narrowingKeys.
	Narrowed bool
	// Conditional means the statement has a condition of any kind. A Deny that carries one
	// may not apply to the request an attacker makes - "deny unless over TLS" does not stop
	// one who uses TLS - so only an unconditional Deny closes what an Allow opens.
	Conditional bool
	// URLOnly means the statement holds only for calls through a Lambda function URL: a
	// condition on lambda:InvokedViaFunctionUrl or lambda:FunctionUrlAuthType is met by no
	// other call. URLAuthType is the auth type the latter requires.
	URLOnly     bool
	URLAuthType string
	// DeniesOutside means a Deny that holds for every caller outside a fixed set: "deny
	// unless from these addresses", "unless through this VPC endpoint". Unlike a Deny that
	// holds only without TLS, it is one an attacker on the internet cannot step around.
	DeniesOutside bool
}

// narrowingKeys are the condition keys whose fixed values make a statement non-public, as
// S3 Block Public Access lists them: the caller's account, organization or identity, its
// source network, the resource or account calling on its behalf, an access point.
var narrowingKeys = map[string]bool{
	"aws:principalorgid": true, "aws:principalaccount": true, "aws:principalarn": true,
	"aws:sourceip": true, "aws:sourcevpc": true, "aws:sourcevpce": true,
	"aws:sourcearn": true, "aws:sourceaccount": true, "aws:sourceowner": true,
	"aws:userid": true, "s3:dataaccesspointarn": true, "s3:dataaccesspointaccount": true,
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
		// API Gateway hands a REST API's policy back escaped - {\"Version\":…,
		// \"Resource\":\"arn:…\/*\"} - which is the body of a JSON string, not JSON.
		// Undoing every escape JSON allows, \/ included, gives the document back.
		if !json.Valid(doc) && strings.Contains(v, `\"`) {
			if unq, ok := unescapeJSONString(v); ok && json.Valid([]byte(unq)) {
				doc = []byte(unq)
			}
		}
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
			for op, block := range cond {
				keys, _ := block.(map[string]any)
				for k, v := range keys {
					key, vals := strings.ToLower(k), condValues(v)
					s.Conditional = true
					switch key {
					case "lambda:invokedviafunctionurl":
						s.URLOnly = s.URLOnly || (len(vals) == 1 && strings.EqualFold(vals[0], "true"))
					case "lambda:functionurlauthtype":
						s.URLOnly = true
						if len(vals) == 1 {
							s.URLAuthType = strings.ToUpper(vals[0])
						}
					}
					if narrowingOperator(op) && narrowingKeys[key] && allFixed(key, vals) {
						s.Narrowed = true
					}
					if negatedOperator(op) && narrowingKeys[key] && allFixed(key, vals) {
						s.DeniesOutside = true
					}
				}
			}
		}
		if s.Allow {
			s.DeniesOutside = false
		}
		out.Statements = append(out.Statements, s)
	}
	return out, nil
}

// unescapeJSONString undoes the escapes of the body of a JSON string - \" \\ \/ \b \f \n
// \r \t and \uXXXX, surrogate pairs included - reading the escapes one by one rather than
// putting the body between quotes for a decoder, which a stray quote in it could break out
// of. ok is false when s is no such body: an escape JSON does not allow, or a quote or
// control character left bare.
func unescapeJSONString(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c < 0x20 {
			return "", false
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i++; i == len(s) {
			return "", false
		}
		switch s[i] {
		case '"', '\\', '/':
			b.WriteByte(s[i])
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r, ok := hex4(s, i+1)
			if !ok {
				return "", false
			}
			i += 4
			if utf16.IsSurrogate(r) && strings.HasPrefix(s[i+1:], `\u`) {
				if lo, ok := hex4(s, i+3); ok {
					if pair := utf16.DecodeRune(r, lo); pair != utf8.RuneError {
						r, i = pair, i+6
					}
				}
			}
			b.WriteRune(r) // a lone surrogate becomes U+FFFD, as encoding/json makes it
		default:
			return "", false
		}
	}
	return b.String(), true
}

// hex4 reads the four hex digits of a \u escape that start at s[i].
func hex4(s string, i int) (rune, bool) {
	if i+4 > len(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s[i:i+4], 16, 16)
	return rune(n), err == nil
}

// Public reports whether the policy lets anyone perform one of the actions in a call made
// directly, not through a Lambda function URL: an Allow naming every principal, not
// narrowed by a condition, and no unconditional Deny of every principal over that action.
func (p ResourcePolicy) Public(actions ...string) bool { return p.public(false, "", actions) }

// PublicThroughURL is Public for a call through a Lambda function URL of the given auth
// type: statements confined to such calls count too, unless they require another type.
func (p ResourcePolicy) PublicThroughURL(authType string, actions ...string) bool {
	return p.public(true, authType, actions)
}

func (p ResourcePolicy) public(viaURL bool, authType string, actions []string) bool {
	allowed := false
	for _, s := range p.Statements {
		if !s.anyone() || !s.covers(actions) || s.Narrowed {
			continue
		}
		if s.URLOnly && (!viaURL || (s.URLAuthType != "" && !strings.EqualFold(s.URLAuthType, authType))) {
			continue
		}
		if !s.Allow {
			if s.Conditional {
				continue
			}
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

// Confined reports whether the policy denies one of the actions to every caller outside a
// fixed set of addresses, endpoints or identities - which an attacker on the internet is
// outside of, whatever an Allow elsewhere in the policy grants.
func (p ResourcePolicy) Confined(actions ...string) bool {
	for _, s := range p.Statements {
		if s.DeniesOutside && s.anyone() && s.covers(actions) {
			return true
		}
	}
	return false
}

// negatedOperator reports whether a condition operator holds for every value but the ones
// listed: on a Deny, it denies everyone outside them.
func negatedOperator(op string) bool {
	switch strings.TrimSuffix(strings.ToLower(op), "ifexists") {
	case "stringnotequals", "stringnotequalsignorecase", "stringnotlike", "arnnotequals", "arnnotlike", "notipaddress":
		return true
	}
	return false
}

// narrowingOperator reports whether a condition operator confines a key to its values. The
// negated operators confine nothing a stranger cannot avoid; an ...IfExists operator, and
// ForAllValues, also hold when the key is absent from the request.
func narrowingOperator(op string) bool {
	switch strings.TrimPrefix(strings.ToLower(op), "foranyvalue:") {
	case "stringequals", "stringequalsignorecase", "stringlike", "arnequals", "arnlike", "ipaddress":
		return true
	}
	return false
}

// allFixed reports whether every value of a condition is a fixed one: no wildcard, no
// policy variable, and for a source IP no range wider than /8 (IPv4) or /32 (IPv6), which
// AWS counts as everyone.
func allFixed(key string, vals []string) bool {
	if len(vals) == 0 {
		return false
	}
	for _, v := range vals {
		if !fixedValue(key, v) {
			return false
		}
	}
	return true
}

func fixedValue(key, v string) bool {
	if v == "" || strings.Contains(v, "${") {
		return false
	}
	switch key {
	case "aws:sourceip":
		if !strings.Contains(v, "/") {
			return net.ParseIP(v) != nil
		}
		ip, n, err := net.ParseCIDR(v)
		if err != nil {
			return false
		}
		ones, _ := n.Mask.Size()
		if ip.To4() != nil {
			return ones >= 8
		}
		return ones >= 32
	case "aws:userid":
		// Every session of one role, "AROA…:*", is still that role.
		if id, rest, ok := strings.Cut(v, ":"); ok && rest == "*" && id != "" && !strings.ContainsAny(id, "*?") {
			return true
		}
	case "s3:dataaccesspointarn":
		// Any access point of one account: the name may be a wildcard, the account may not.
		if i := strings.Index(v, ":accesspoint/"); i >= 0 {
			return !strings.ContainsAny(v[:i], "*?")
		}
	}
	return !strings.ContainsAny(v, "*?")
}

// condValues reads a condition's values: a string, a list, or a JSON bool or number.
func condValues(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case nil:
		return nil
	}
	return []string{fmt.Sprint(v)}
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
