package analyzer

import (
	"math"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestWeightCauseOf(t *testing.T) {
	cve := ontology.Node{ID: "CVE:1", Label: ontology.LabelCVE, Name: "cve-2021-44228"}
	weakness := ontology.Node{ID: "Weakness:1", Label: ontology.LabelWeakness, Name: "dangerous-subprocess-use"}
	role := ontology.Node{ID: "IAM_Role:1", Label: ontology.LabelIAMRole, Name: "payments-admin"}
	cases := []struct {
		name string
		e    ontology.Edge
		to   ontology.Node
		want string
	}{
		// The probability on an edge into a CVE is the CVE's own (KEV, EPSS, severity), so
		// the CVE is the cause - upper-cased, the way a feed would name it.
		{"into a CVE", ontology.Edge{Type: ontology.EdgeAffects, To: cve.ID}, cve, "CVE-2021-44228"},
		{"into a CVE with no name", ontology.Edge{Type: ontology.EdgeAffects, To: "CVE:2"}, ontology.Node{ID: "CVE:2", Label: ontology.LabelCVE}, "CVE:2"},
		// A feed that says what the cause is, is believed.
		{"declared by the feed", ontology.Edge{Type: ontology.EdgeAffects, To: cve.ID, Properties: map[string]any{ontology.PropWeightCause: "leaked-key-1"}}, cve, "leaked-key-1"},
		// What exploiting the CVE reaches is a different event, with its own draw.
		{"out of a CVE", ontology.Edge{Type: ontology.EdgeExploits, From: cve.ID, To: role.ID}, role, ""},
		// A code weakness is one finding in one place, not a shared vulnerability.
		{"into a code weakness", ontology.Edge{Type: ontology.EdgeAffects, To: weakness.ID}, weakness, ""},
		{"a topology edge", ontology.Edge{Type: ontology.EdgeExposes, To: role.ID}, role, ""},
	}
	for _, c := range cases {
		if got := weightCauseOf(c.e, c.to); got != c.want {
			t.Errorf("%s: cause %q, want %q", c.name, got, c.want)
		}
	}
}

// oneCVEOnTwoPackages is the shape a Debian-based image gives Trivy all the time: one CVE
// reported on two packages that ship the same library (libssl3 and openssl), so two
// AFFECTS edges into one CVE node. targetLabel lets the control below swap the CVE for a
// node the cause is not inferred for, with everything else equal.
func oneCVEOnTwoPackages(targetLabel ontology.Label) graph.Snapshot {
	return graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb", Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "c", Label: ontology.LabelContainer, Name: "api"},
			{ID: "img", Label: ontology.LabelImage, Name: "api:1.0"},
			{ID: "libssl3", Label: ontology.LabelLibrary, Name: "libssl3@3.0.11"},
			{ID: "openssl", Label: ontology.LabelLibrary, Name: "openssl@3.0.11"},
			{ID: "vuln", Label: targetLabel, Name: "CVE-2024-0727"},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "admin", Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeExposes, From: "lb", To: "c", ExploitProbability: 1.0},
			{Type: ontology.EdgeHosts, From: "c", To: "img", ExploitProbability: 1.0},
			{Type: ontology.EdgeDependsOn, From: "img", To: "libssl3", ExploitProbability: 1.0},
			{Type: ontology.EdgeDependsOn, From: "img", To: "openssl", ExploitProbability: 1.0},
			{Type: ontology.EdgeAffects, From: "libssl3", To: "vuln", ExploitProbability: 0.5},
			{Type: ontology.EdgeAffects, From: "openssl", To: "vuln", ExploitProbability: 0.5},
			{Type: ontology.EdgeExploits, From: "vuln", To: "role", ExploitProbability: 1.0},
		},
	}
}

// One weakness is one chance. Drawn independently, the two edges into the CVE gave the
// attacker 1-(1-0.5)² = 75% of getting through a vulnerability whose own probability is
// 50%, because the package manager happens to ship the library in two pieces. Coupled on
// the CVE, it is the CVE's 50% - and the control shows it is the inferred cause that makes
// the difference, not anything else about the graph.
func TestOneCVEOnTwoPackagesIsOneChance(t *testing.T) {
	coupled := mustSimulate(t, oneCVEOnTwoPackages(ontology.LabelCVE), 20000, 1).AnyCompromiseProbability
	if math.Abs(coupled-0.5) > 0.02 {
		t.Errorf("one CVE on two packages: P(jewel) = %.4f, want ≈ 0.50 - the CVE holds or it does not", coupled)
	}
	control := mustSimulate(t, oneCVEOnTwoPackages(ontology.LabelWeakness), 20000, 1).AnyCompromiseProbability
	if math.Abs(control-0.75) > 0.02 {
		t.Errorf("control (no shared cause): P(jewel) = %.4f, want ≈ 0.75", control)
	}
}

// The path carries the cause it rests on, so the API shows which hop is the CVE.
func TestCriticalPathCarriesTheInferredCause(t *testing.T) {
	paths := FindCriticalPaths(oneCVEOnTwoPackages(ontology.LabelCVE))
	if len(paths) == 0 {
		t.Fatal("no critical path")
	}
	var causes []string
	for _, s := range paths[0].Steps {
		if s.WeightCause != "" {
			causes = append(causes, string(s.EdgeType)+":"+s.WeightCause)
		}
	}
	if len(causes) != 1 || causes[0] != string(ontology.EdgeAffects)+":CVE-2024-0727" {
		t.Errorf("causes on the path = %v, want exactly the AFFECTS hop into CVE-2024-0727", causes)
	}
}
