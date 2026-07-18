package analyzer

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// TestCredentialExposedIsASeed proves the opt-in credential-origin threat model: a node
// flagged credential_exposed originates paths exactly like an internet-exposed one, so a
// leaked-credential identity that can escalate to a crown jewel surfaces as a scored path -
// while a plain identity with no seed flag originates nothing (the internet-origin default).
func TestCredentialExposedIsASeed(t *testing.T) {
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "u", Label: ontology.LabelUser, Name: "alice",
				Properties: map[string]any{ontology.PropCredentialExposed: true}},
			{ID: "admin", Label: ontology.LabelIAMRole, Name: "account-admin",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeCanEscalateTo, From: "u", To: "admin", ExploitProbability: 0.9},
		},
	}
	if got := FindCriticalPaths(snap); len(got) != 1 {
		t.Fatalf("a credential-exposed identity should seed one path to the jewel, got %d", len(got))
	}

	snap.Nodes[0].Properties = map[string]any{} // no seed flag
	if got := FindCriticalPaths(snap); len(got) != 0 {
		t.Errorf("without a seed flag a plain identity must not originate a path, got %d", len(got))
	}
}
