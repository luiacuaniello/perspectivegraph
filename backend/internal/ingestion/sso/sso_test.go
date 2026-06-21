package sso

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestFederationChain(t *testing.T) {
	in := `{"provider":"okta","users":[
	  {"email":"alice@acme.com","mfa":false,"admin":true,
	   "federated_roles":["arn:aws:iam::123456789012:role/AdminRole"]}]}`
	events, err := New().Parse(strings.NewReader(in), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ev := events[0]

	idpID := ontology.NewID(ontology.LabelIdentityProvider, "okta")
	userID := ontology.NewID(ontology.LabelUser, "alice@acme.com")
	roleID := ontology.NewID(ontology.LabelIAMRole, "arn:aws:iam::123456789012:role/AdminRole")

	// IdP is an internet-facing entry point.
	idp := findNode(ev.Nodes, idpID)
	if idp == nil || !idp.Bool(ontology.PropInternetExposed) {
		t.Fatalf("IdP should exist and be internet-exposed, got %+v", idp)
	}
	// AUTHENTICATES idp->user and ASSUMES user->role (ARN-keyed → converges with IAM).
	if !hasEdge(ev.Edges, ontology.EdgeAuthenticates, idpID, userID) {
		t.Error("missing AUTHENTICATES idp->user")
	}
	if !hasEdge(ev.Edges, ontology.EdgeAssumes, userID, roleID) {
		t.Error("missing ASSUMES user->federated role")
	}
	// No MFA → the auth edge is highly traversable.
	for _, e := range ev.Edges {
		if e.Type == ontology.EdgeAuthenticates && e.ExploitProbability < 0.6 {
			t.Errorf("no-MFA auth edge should be high-probability, got %v", e.ExploitProbability)
		}
	}
}

func TestMFADiscountsAuthEdge(t *testing.T) {
	in := `{"provider":"okta","users":[{"email":"bob@acme.com","mfa":true}]}`
	events, _ := New().Parse(strings.NewReader(in), ingestion.Options{})
	for _, e := range events[0].Edges {
		if e.Type == ontology.EdgeAuthenticates && e.ExploitProbability >= 0.6 {
			t.Errorf("MFA-enforced user's auth edge should be discounted, got %v", e.ExploitProbability)
		}
	}
}

func findNode(nodes []ontology.Node, id string) *ontology.Node {
	for i := range nodes {
		if nodes[i].ID == id {
			return &nodes[i]
		}
	}
	return nil
}

func hasEdge(edges []ontology.Edge, t ontology.EdgeType, from, to string) bool {
	for _, e := range edges {
		if e.Type == t && e.From == from && e.To == to {
			return true
		}
	}
	return false
}
