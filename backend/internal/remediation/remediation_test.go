package remediation

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestGenerateNetworkPolicyForExposedContainer(t *testing.T) {
	p := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-alb"},
			{ID: "c", Label: ontology.LabelContainer, Name: "payments",
				Properties: map[string]any{"k8s_ns": "prod"}},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "payments-admin",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeExposes, From: "lb", To: "c"},
			{EdgeType: ontology.EdgeAssumes, From: "c", To: "role"},
		},
	}

	sugs := Generate(p)
	if len(sugs) != 2 {
		t.Fatalf("expected 2 suggestions (netpol + iam), got %d", len(sugs))
	}

	byKind := map[string]Suggestion{}
	for _, s := range sugs {
		byKind[s.Kind] = s
	}

	np, ok := byKind["k8s-networkpolicy"]
	if !ok {
		t.Fatal("expected a k8s-networkpolicy suggestion")
	}
	for _, want := range []string{"kind: NetworkPolicy", "namespace: prod", "app: payments", "ingress: []"} {
		if !strings.Contains(np.Content, want) {
			t.Errorf("network policy missing %q:\n%s", want, np.Content)
		}
	}

	tf, ok := byKind["terraform"]
	if !ok {
		t.Fatal("expected a terraform IAM suggestion")
	}
	if !strings.Contains(tf.Content, "least-privilege") {
		t.Errorf("terraform should scope down the role:\n%s", tf.Content)
	}
}

func TestGenerateCloudPath(t *testing.T) {
	p := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "public-alb"},
			{ID: "vm", Label: ontology.LabelVirtualMachine, Name: "web"},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "web-admin", Properties: map[string]any{ontology.PropCrownJewel: true}},
			{ID: "bucket", Label: ontology.LabelBucket, Name: "customer-exports", Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeRoutesTo, From: "lb", To: "vm"},
			{EdgeType: ontology.EdgeAssumes, From: "vm", To: "role"},
			{EdgeType: ontology.EdgeHasPermission, From: "role", To: "bucket"},
		},
	}
	sugs := Generate(p)
	// SG revoke + IAM scope-down + data-store policy = 3.
	if len(sugs) != 3 {
		t.Fatalf("expected 3 suggestions, got %d: %+v", len(sugs), sugs)
	}
}

func TestGeneratePrivescAndLateralPaths(t *testing.T) {
	// IAM privesc: a publicly-assumable role escalates to account-admin.
	privesc := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "r", Label: ontology.LabelIAMRole, Name: "public-deployer",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "admin", Label: ontology.LabelIAMRole, Name: "account-admin (effective)",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{{EdgeType: ontology.EdgeCanEscalateTo, From: "r", To: "admin"}},
	}
	sugs := Generate(privesc)
	if len(sugs) != 1 {
		t.Fatalf("privesc path: expected 1 suggestion, got %d", len(sugs))
	}
	s := sugs[0]
	for _, want := range []string{`Effect   = "Deny"`, "iam:PassRole", "iam:CreatePolicyVersion", "publicly assumable"} {
		if !strings.Contains(s.Content, want) {
			t.Errorf("privesc remediation missing %q:\n%s", want, s.Content)
		}
	}
	// Apply-ready: the deny policy must not carry a REPLACE placeholder.
	if strings.Contains(s.Content, "REPLACE_WITH") {
		t.Errorf("privesc deny policy should be apply-ready, found a placeholder:\n%s", s.Content)
	}

	// Cloud lateral movement: a CONNECTS_TO edge must produce a segmentation fix.
	lateral := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "web", Label: ontology.LabelVirtualMachine, Name: "web-tier",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "db", Label: ontology.LabelVirtualMachine, Name: "customer-db",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{{EdgeType: ontology.EdgeConnectsTo, From: "web", To: "db"}},
	}
	lat := Generate(lateral)
	if len(lat) != 1 || !strings.Contains(lat[0].Content, "lateral reachability") {
		t.Fatalf("lateral path: expected a segmentation suggestion, got %+v", lat)
	}
}
