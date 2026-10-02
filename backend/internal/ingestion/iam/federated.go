package iam

import (
	"sort"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// oidcIssuer is a public, multi-tenant OIDC issuer: anyone can open an account there and
// obtain a token from it. A role that trusts one without pinning who the token was issued
// to trusts everyone with such an account.
type oidcIssuer struct {
	host    string // the issuer as it appears in the provider ARN
	name    string // how a route names it
	subject string // the condition key that says who the token was issued to
	// pinned reports whether a subject pattern the trust accepts names one owner.
	pinned func(pattern string) bool
}

// publicIssuers are the issuers whose open trusts are reported. GitHub Actions first: in
// 2023 roles that checked only the audience were found assumable from any repository on
// GitHub, Datadog later counted hundreds in customer accounts, and the pattern has been
// exploited to reach account administrator. AWS no longer accepts new trust policies like
// that; the ones created before still work.
var publicIssuers = []oidcIssuer{
	{host: "token.actions.githubusercontent.com", name: "GitHub Actions",
		subject: "token.actions.githubusercontent.com:sub", pinned: githubSubjectPinned},
}

// githubSubjectPinned reports whether a GitHub Actions subject pattern names one owner. The
// default subject is repo:OWNER/REPO:…; a pattern pins only if the owner is spelled out -
// repo:acme/* is any repository of acme, repo:* or repo:ac*/x is any owner's. A subject
// built from a custom template (repository_owner_id:…, job_workflow_ref:…) is taken as
// pinned unless it is nothing but wildcards: reading every template is not done here.
func githubSubjectPinned(p string) bool {
	if strings.Trim(p, "*?") == "" {
		return false
	}
	rest, ok := strings.CutPrefix(strings.ToLower(p), "repo:")
	if !ok {
		return true
	}
	end := strings.IndexAny(rest, "/:")
	if end <= 0 {
		return false
	}
	return !strings.ContainsAny(rest[:end], "*?")
}

// federatedTrust is a trust a role places in a public OIDC issuer.
type federatedTrust struct {
	issuer oidcIssuer
	// subjects are the subject patterns the trust accepts, sorted; empty means any.
	subjects []string
	// open means anyone with an account on the issuer can assume the role: no subject
	// is required, or one accepted pattern does not name an owner.
	open bool
}

// federatedTrusts reads the trusts a role's trust policy places in public OIDC issuers.
// Conditions on other keys are not read: the audience is chosen by whoever requests the
// token, so it pins nothing.
func federatedTrusts(doc policyDoc) []federatedTrust {
	var out []federatedTrust
	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") || !allowsWebIdentity(st.Action) {
			continue
		}
		for _, fed := range st.Principal.Federated {
			issuer, ok := publicIssuer(fed)
			if !ok {
				continue
			}
			subjects := subjectPatterns(st.Condition, issuer.subject)
			open := len(subjects) == 0
			for _, s := range subjects {
				if !issuer.pinned(s) {
					open = true
				}
			}
			out = append(out, federatedTrust{issuer: issuer, subjects: subjects, open: open})
		}
	}
	return out
}

// allowsWebIdentity reports whether the statement's actions include
// sts:AssumeRoleWithWebIdentity, the call that trades an OIDC token for the role.
func allowsWebIdentity(actions stringOrSlice) bool {
	for _, a := range actions {
		if matchAction(a, "sts:AssumeRoleWithWebIdentity") {
			return true
		}
	}
	return false
}

// publicIssuer matches a Federated principal - an OIDC provider ARN
// (arn:aws:iam::ACCOUNT:oidc-provider/HOST) or the bare host - to a public issuer.
func publicIssuer(federated string) (oidcIssuer, bool) {
	host := federated
	if _, after, ok := strings.Cut(federated, ":oidc-provider/"); ok {
		host = after
	}
	for _, iss := range publicIssuers {
		if strings.EqualFold(host, iss.host) {
			return iss, true
		}
	}
	return oidcIssuer{}, false
}

// subjectPatterns collects the values a Condition requires the subject key to match.
// Only the operators that restrict to the listed values count; StringNotEquals and the
// like let everyone else in, so they pin nothing.
func subjectPatterns(cond map[string]any, key string) []string {
	var out []string
	for op, raw := range cond {
		bare := op
		if _, after, ok := strings.Cut(bare, ":"); ok { // ForAnyValue: / ForAllValues:
			bare = after
		}
		bare = strings.TrimSuffix(bare, "IfExists")
		switch strings.ToLower(bare) {
		case "stringequals", "stringlike", "stringequalsignorecase":
		default:
			continue
		}
		block, _ := raw.(map[string]any)
		for k, v := range block {
			if !strings.EqualFold(k, key) {
				continue
			}
			switch vv := v.(type) {
			case string:
				out = append(out, vv)
			case []any:
				for _, x := range vv {
					if s, ok := x.(string); ok {
						out = append(out, s)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// federatedNode is the identity provider a route enters through: one node per issuer and
// accepted subjects, an entry point only when the trust is open.
func federatedNode(ft federatedTrust) ontology.Node {
	scope := "*"
	name := ft.issuer.name + " (any repository)"
	if !ft.open {
		scope = strings.Join(ft.subjects, ",")
		name = ft.issuer.name + " (" + strings.Join(ft.subjects, ", ") + ")"
	}
	props := map[string]any{
		"idp":         strings.ToLower(strings.ReplaceAll(ft.issuer.name, " ", "-")),
		"oidc_issuer": ft.issuer.host,
	}
	if len(ft.subjects) > 0 {
		props["oidc_subjects"] = strings.Join(ft.subjects, ",")
	}
	if ft.open {
		props[ontology.PropInternetExposed] = true
		props["trust_note"] = "the role trusts " + ft.issuer.name + " without pinning " + ft.issuer.subject +
			" to an owner, so a workflow in any account on the issuer can assume it"
	}
	return ontology.Node{
		ID:         ontology.NewID(ontology.LabelIdentityProvider, "oidc", ft.issuer.host, scope),
		Label:      ontology.LabelIdentityProvider,
		Name:       name,
		Properties: props,
	}
}
