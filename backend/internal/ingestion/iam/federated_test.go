package iam

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A GitHub Actions subject pins the role to an owner only if the owner is spelled out.
func TestGitHubSubjectPinned(t *testing.T) {
	for p, want := range map[string]bool{
		"repo:acme/payments:ref:refs/heads/main": true,
		"repo:acme/payments:*":                   true,
		"repo:acme/*":                            true, // any repository of acme: an owner, not everyone
		"repo:*":                                 false,
		"repo:*/payments:*":                      false,
		"repo:ac*/payments":                      false, // any owner whose name starts "ac"
		"repo:ac?me/x":                           false,
		"*":                                      false,
		"repository_owner_id:123:repository_id:456": true, // custom template, taken as pinned
	} {
		if got := githubSubjectPinned(p); got != want {
			t.Errorf("githubSubjectPinned(%q) = %v, want %v", p, got, want)
		}
	}
}

// Each trust shape a role can place in GitHub Actions, and what the graph must say about it.
func TestFederatedTrustShapes(t *testing.T) {
	const provider = `"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"`
	trust := func(stmt string) string {
		return `{"RoleDetailList":[{"RoleName":"deploy","Arn":"arn:aws:iam::1:role/deploy",
		  "AssumeRolePolicyDocument":{"Statement":[` + stmt + `]}}]}`
	}
	webIdentity := func(cond string) string {
		s := `{"Effect":"Allow","Principal":{"Federated":` + provider + `},"Action":"sts:AssumeRoleWithWebIdentity"`
		if cond != "" {
			s += `,"Condition":` + cond
		}
		return s + `}`
	}
	const aud = `"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"`
	for _, c := range []struct {
		name    string
		bundle  string
		idp     bool // an identity provider node is drawn
		open    bool // ... and it is an entry point
		subject string
	}{
		{"no condition at all", trust(webIdentity("")), true, true, ""},
		{"only the audience checked", trust(webIdentity(`{"StringEquals":{` + aud + `}}`)), true, true, ""},
		{"one repository", trust(webIdentity(`{"StringEquals":{` + aud + `,"token.actions.githubusercontent.com:sub":"repo:acme/payments:ref:refs/heads/main"}}`)),
			true, false, "repo:acme/payments:ref:refs/heads/main"},
		{"every repository of one owner", trust(webIdentity(`{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*"}}`)),
			true, false, "repo:acme/*"},
		{"any owner by wildcard", trust(webIdentity(`{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}`)),
			true, true, "repo:*"},
		{"one pinned, one wildcard", trust(webIdentity(`{"StringLike":{"token.actions.githubusercontent.com:sub":["repo:acme/payments:*","*"]}}`)),
			true, true, "*,repo:acme/payments:*"},
		{"a negation pins nothing", trust(webIdentity(`{"StringNotEquals":{"token.actions.githubusercontent.com:sub":"repo:evil/x"}}`)),
			true, true, ""},
		{"IfExists still pins", trust(webIdentity(`{"StringEqualsIfExists":{"token.actions.githubusercontent.com:sub":"repo:acme/payments:ref:refs/heads/main"}}`)),
			true, false, "repo:acme/payments:ref:refs/heads/main"},
		{"bare issuer, sts:* action", trust(`{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:*"}`),
			true, true, ""},
		{"not a web-identity trust", trust(`{"Effect":"Allow","Principal":{"Federated":` + provider + `},"Action":"sts:AssumeRole"}`),
			false, false, ""},
		{"a cluster's own issuer is not public", trust(`{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABC"},"Action":"sts:AssumeRoleWithWebIdentity"}`),
			false, false, ""},
	} {
		events, err := New().Parse(strings.NewReader(c.bundle), ingestion.Options{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var idps []ontology.Node
		var role ontology.Node
		edges := 0
		for _, ev := range events {
			for _, n := range ev.Nodes {
				switch n.Label {
				case ontology.LabelIdentityProvider:
					idps = append(idps, n)
				case ontology.LabelIAMRole:
					if n.Name == "deploy" {
						role = n
					}
				}
			}
			for _, e := range ev.Edges {
				if e.Type == ontology.EdgeAuthenticates && e.To == role.ID {
					edges++
				}
			}
		}
		if got := len(idps) == 1; got != c.idp {
			t.Errorf("%s: identity providers %+v, want one: %v", c.name, idps, c.idp)
			continue
		}
		if !c.idp {
			continue
		}
		idp := idps[0]
		if idp.Bool(ontology.PropInternetExposed) != c.open || role.Bool("federated_trust_open") != c.open {
			t.Errorf("%s: open = %v (role %v), want %v", c.name, idp.Bool(ontology.PropInternetExposed), role.Bool("federated_trust_open"), c.open)
		}
		if got, _ := idp.Properties["oidc_subjects"].(string); got != c.subject {
			t.Errorf("%s: subjects %q, want %q", c.name, got, c.subject)
		}
		if edges != 1 {
			t.Errorf("%s: %d AUTHENTICATES edges into the role, want one", c.name, edges)
		}
	}
}
