package remediation

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Two high-risk paths share a single container; one network-policy fix should
// cut both and lead the plan, ahead of a fix that only touches the third path.
func TestPlanPrioritizesSharedChokePoint(t *testing.T) {
	container := ontology.Node{ID: "Container:web", Label: ontology.LabelContainer, Name: "web"}
	lb := ontology.Node{ID: "LoadBalancer:edge", Label: ontology.LabelLoadBalancer, Name: "edge"}
	role := ontology.Node{ID: "IAM_Role:admin", Label: ontology.LabelIAMRole, Name: "admin",
		Properties: map[string]any{ontology.PropCrownJewel: true}}
	bucket := ontology.Node{ID: "Bucket:pii", Label: ontology.LabelBucket, Name: "pii"}
	vm := ontology.Node{ID: "VirtualMachine:legacy", Label: ontology.LabelVirtualMachine, Name: "legacy"}

	// Paths A and B both traverse the container (EXPOSES → container).
	pathA := analyzer.AttackPath{ID: "A", Score: 0.6,
		Nodes: []ontology.Node{lb, container, role},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeExposes, From: lb.ID, To: container.ID},
			{EdgeType: ontology.EdgeAssumes, From: container.ID, To: role.ID},
		}}
	pathB := analyzer.AttackPath{ID: "B", Score: 0.5,
		Nodes: []ontology.Node{lb, container, bucket},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeExposes, From: lb.ID, To: container.ID},
			{EdgeType: ontology.EdgeHasPermission, From: container.ID, To: bucket.ID},
		}}
	// Path C is independent (LB → VM only).
	pathC := analyzer.AttackPath{ID: "C", Score: 0.4,
		Nodes: []ontology.Node{lb, vm, role},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeRoutesTo, From: lb.ID, To: vm.ID},
			{EdgeType: ontology.EdgeAssumes, From: vm.ID, To: role.ID},
		}}

	plan := Plan([]analyzer.AttackPath{pathA, pathB, pathC})
	if len(plan) == 0 {
		t.Fatal("expected a non-empty plan")
	}

	// The container isolation fix must come first and be credited with A and B.
	first := plan[0]
	if first.Suggestion.Kind != "k8s-networkpolicy" {
		t.Fatalf("top fix kind = %q, want k8s-networkpolicy (the shared choke point)", first.Suggestion.Kind)
	}
	if first.PathCount != 2 {
		t.Errorf("top fix cuts %d paths, want 2 (A and B)", first.PathCount)
	}
	if first.RiskCovered < 1.09 || first.RiskCovered > 1.11 {
		t.Errorf("top fix risk = %.3f, want ~1.1 (0.6+0.5)", first.RiskCovered)
	}

	// Coverage is marginal and never double-counts a path.
	seen := map[string]bool{}
	cumulative := 0.0
	for _, f := range plan {
		cumulative += f.CoveragePct
		for _, id := range f.PathsCut {
			if seen[id] {
				t.Errorf("path %s credited to more than one fix", id)
			}
			seen[id] = true
		}
	}
	if cumulative > 1.0001 {
		t.Errorf("cumulative coverage %.3f exceeds 1.0", cumulative)
	}
}
