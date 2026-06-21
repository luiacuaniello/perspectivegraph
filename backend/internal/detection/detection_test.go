package detection

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestGeneratesFalcoAndSigmaForWorkload(t *testing.T) {
	path := analyzer.AttackPath{
		ID: "ap-test",
		Nodes: []ontology.Node{
			{Label: ontology.LabelLoadBalancer, Name: "edge-alb"},
			{Label: ontology.LabelContainer, Name: "payments", Properties: map[string]any{"k8s_ns": "prod"}},
			{Label: ontology.LabelCVE, Name: "CVE-2021-44228"},
			{Label: ontology.LabelIAMRole, Name: "admin", Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
	}
	dets := Generate(path)
	if len(dets) != 2 {
		t.Fatalf("want falco+sigma (2), got %d", len(dets))
	}
	kinds := map[string]string{}
	for _, d := range dets {
		kinds[d.Kind] = d.Content
	}
	falco, ok := kinds["falco"]
	if !ok {
		t.Fatal("missing falco rule")
	}
	for _, want := range []string{`container.name = "payments"`, `k8s.ns.name = "prod"`, "ap-test", "CVE-2021-44228", "admin"} {
		if !strings.Contains(falco, want) {
			t.Errorf("falco rule missing %q", want)
		}
	}
	sigma, ok := kinds["sigma"]
	if !ok {
		t.Fatal("missing sigma rule")
	}
	if !strings.Contains(sigma, "process_creation") || !strings.Contains(sigma, "attack.t1059") {
		t.Errorf("sigma rule malformed:\n%s", sigma)
	}
}

func TestNoWorkloadNoDetection(t *testing.T) {
	path := analyzer.AttackPath{ID: "x", Nodes: []ontology.Node{
		{Label: ontology.LabelLoadBalancer, Name: "lb"},
		{Label: ontology.LabelBucket, Name: "data"},
	}}
	if d := Generate(path); len(d) != 0 {
		t.Errorf("no container/VM on path → no detections; got %d", len(d))
	}
}
