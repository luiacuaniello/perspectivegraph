package analyzer

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestWeightBasisOf(t *testing.T) {
	cve := ontology.Node{ID: "CVE:x", Label: ontology.LabelCVE, Properties: map[string]any{ontology.PropCVSS: 9.8}}
	cveNoScore := ontology.Node{ID: "CVE:y", Label: ontology.LabelCVE}
	role := ontology.Node{ID: "IAM:r", Label: ontology.LabelIAMRole}
	hot := ontology.Node{ID: "C:1", Label: ontology.LabelContainer, Properties: map[string]any{ontology.PropRuntimeAlert: true}}

	cases := []struct {
		name       string
		edge       ontology.Edge
		from, to   ontology.Node
		wantBasis  string
		wantConfGt float64 // lower bound sanity
	}{
		{"intel kev wins", ontology.Edge{Type: ontology.EdgeAffects, Properties: map[string]any{ontology.PropWeightBasis: "kev"}}, ontology.Node{}, cve, "kev", 0.9},
		{"runtime evidence", ontology.Edge{Type: ontology.EdgeExposes}, hot, role, "runtime", 0.8},
		{"cvss-anchored vuln", ontology.Edge{Type: ontology.EdgeAffects}, ontology.Node{}, cve, "cvss", 0.5},
		{"bare severity guess", ontology.Edge{Type: ontology.EdgeExploits}, ontology.Node{}, cveNoScore, "severity", 0.3},
		{"topology heuristic", ontology.Edge{Type: ontology.EdgeExposes}, role, role, "heuristic", 0.3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			basis, conf, _ := weightBasisOf(tc.edge, tc.from, tc.to)
			if basis != tc.wantBasis {
				t.Errorf("basis = %q, want %q", basis, tc.wantBasis)
			}
			if conf <= tc.wantConfGt {
				t.Errorf("confidence %v should exceed %v for %q", conf, tc.wantConfGt, basis)
			}
		})
	}
}

func TestPathConfidenceBands(t *testing.T) {
	mk := func(confs ...float64) []Step {
		s := make([]Step, len(confs))
		for i, c := range confs {
			s[i] = Step{WeightConfidence: c}
		}
		return s
	}
	cases := []struct {
		name  string
		steps []Step
		label string
	}{
		{"all evidence", mk(0.95, 0.9, 0.85), "high"},
		{"mixed", mk(0.6, 0.6, 0.4), "medium"},
		{"mostly guesses", mk(0.35, 0.35, 0.4), "low"},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, label := pathConfidence(tc.steps)
			if label != tc.label {
				t.Errorf("label = %q, want %q", label, tc.label)
			}
		})
	}
}

// A path resting on observed exploitation must read as more trustworthy than one
// built from severity/topology guesses, even at the same score.
func TestEvidenceBackedPathIsMoreConfident(t *testing.T) {
	evidence := mkSteps([]string{"kev", "runtime"})
	guesses := mkSteps([]string{"severity", "heuristic"})
	ce, _ := pathConfidence(evidence)
	cg, _ := pathConfidence(guesses)
	if ce <= cg {
		t.Errorf("evidence-backed confidence %v should exceed guess-backed %v", ce, cg)
	}
}

func mkSteps(bases []string) []Step {
	s := make([]Step, len(bases))
	for i, b := range bases {
		s[i] = Step{WeightBasis: b, WeightConfidence: basisConfidence(b)}
	}
	return s
}
