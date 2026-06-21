// Package sso ingests identity-federation from an external IdP (Okta, Entra,
// Google Workspace, …) — the modern breach's front door: phish or stuff an SSO
// user and you inherit every cloud role they federate into. PerspectiveGraph
// models the IdP as an internet-facing entry point, each user it authenticates,
// and the federated cloud roles those users assume:
//
//	IdentityProvider(internet) ──AUTHENTICATES──▶ User ──ASSUMES──▶ IAM_Role
//
// Because the federated role is keyed by its ARN, it converges with the role the
// IAM collector already discovered — so an Okta user with no MFA who federates
// into a role that CAN_ESCALATE_TO account-admin lights up as one path:
// internet → Okta → user → cloud admin.
//
// A directory-sync job posts it (assembled from the Okta/Entra admin API):
//
//	curl -X POST $INGEST/ingest/sso -d '{
//	  "provider": "okta",
//	  "users": [{"email":"alice@acme.com","mfa":false,"federated_roles":[
//	    "arn:aws:iam::123456789012:role/AdminRole"]}]
//	}'
//
// Accepts a single object or a JSON array of them.
package sso

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type directory struct {
	Provider      string `json:"provider"`       // "okta" | "entra" | "google" | …
	InternetLogin *bool  `json:"internet_login"` // SSO portal reachable from the internet (default true)
	Users         []struct {
		Email          string   `json:"email"`
		MFA            bool     `json:"mfa"`             // strong MFA enforced for this user
		Admin          bool     `json:"admin"`           // member of a privileged IdP group
		Groups         []string `json:"groups"`          // IdP group memberships
		FederatedRoles []string `json:"federated_roles"` // cloud role ARNs/names this user can assume
	} `json:"users"`
}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "sso" }

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	records, err := decode(r)
	if err != nil {
		return nil, err
	}

	var nodes []ontology.Node
	var edges []ontology.Edge
	for _, d := range records {
		if d.Provider == "" {
			return nil, fmt.Errorf("sso record needs a provider")
		}
		internetLogin := d.InternetLogin == nil || *d.InternetLogin // default: SSO is internet-facing

		idpID := ontology.NewID(ontology.LabelIdentityProvider, d.Provider)
		idpProps := map[string]any{"idp": d.Provider}
		if internetLogin {
			idpProps[ontology.PropInternetExposed] = true
		}
		nodes = append(nodes, ontology.Node{
			ID: idpID, Label: ontology.LabelIdentityProvider, Name: d.Provider + " (SSO)", Properties: idpProps,
		})

		for _, u := range d.Users {
			if u.Email == "" {
				continue
			}
			userID := ontology.NewID(ontology.LabelUser, u.Email)
			uprops := map[string]any{"idp": d.Provider, "mfa": u.MFA}
			if u.Admin {
				uprops["idp_admin"] = true
			}
			if len(u.Groups) > 0 {
				uprops["groups"] = strings.Join(u.Groups, ",")
			}
			nodes = append(nodes, ontology.Node{ID: userID, Label: ontology.LabelUser, Name: u.Email, Properties: uprops})

			// No MFA → the account is far easier to phish/credential-stuff, so the
			// IdP→user edge is much more traversable. Enforced MFA discounts it.
			authProb := 0.8
			if u.MFA {
				authProb = 0.4
			}
			edges = append(edges, ontology.Edge{
				Type: ontology.EdgeAuthenticates, From: idpID, To: userID, ExploitProbability: authProb,
			})

			for _, role := range u.FederatedRoles {
				if role == "" {
					continue
				}
				roleID := ontology.NewID(ontology.LabelIAMRole, role) // ARN-keyed → converges with the IAM collector
				nodes = append(nodes, ontology.Node{ID: roleID, Label: ontology.LabelIAMRole, Name: shortRole(role)})
				edges = append(edges, ontology.Edge{
					Type: ontology.EdgeAssumes, From: userID, To: roleID, ExploitProbability: 0.9,
				})
			}
		}
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      nodes,
		Edges:      edges,
	}}, nil
}

// shortRole renders the trailing role name from an ARN for display, leaving the
// id (which keys the node) as the full ARN so it converges with the IAM graph.
func shortRole(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}

func decode(r io.Reader) ([]directory, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	for _, c := range data {
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			continue
		}
		if c == '[' {
			var arr []directory
			if err := json.Unmarshal(data, &arr); err != nil {
				return nil, fmt.Errorf("decode sso array: %w", err)
			}
			return arr, nil
		}
		break
	}
	var one directory
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, fmt.Errorf("decode sso record: %w", err)
	}
	return []directory{one}, nil
}
