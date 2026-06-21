package attck

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestForEdgeMapsAttackEdges(t *testing.T) {
	cases := map[ontology.EdgeType]struct {
		id, tacticID string
	}{
		ontology.EdgeExposes:       {"T1190", "TA0001"},
		ontology.EdgeExploits:      {"T1203", "TA0002"},
		ontology.EdgeDependsOn:     {"T1195.002", "TA0001"},
		ontology.EdgeConnectsTo:    {"T1021", "TA0008"},
		ontology.EdgeCanEscalateTo: {"T1078.004", "TA0004"},
		ontology.EdgeEscapesTo:     {"T1611", "TA0004"},
	}
	for edge, want := range cases {
		tech, ok := ForEdge(edge)
		if !ok {
			t.Errorf("%s: expected a technique", edge)
			continue
		}
		if tech.ID != want.id || tech.TacticID != want.tacticID {
			t.Errorf("%s → %s/%s, want %s/%s", edge, tech.ID, tech.TacticID, want.id, want.tacticID)
		}
		if tech.Name == "" || tech.Tactic == "" {
			t.Errorf("%s: technique missing name/tactic: %+v", edge, tech)
		}
	}
}

func TestStructuralEdgesHaveNoTechnique(t *testing.T) {
	for _, e := range []ontology.EdgeType{ontology.EdgeHosts, ontology.EdgeBuiltFrom, ontology.EdgeCompiledInto, ontology.EdgeMitigates} {
		if _, ok := ForEdge(e); ok {
			t.Errorf("%s is structural/defensive and should map to no technique", e)
		}
	}
}

func TestURL(t *testing.T) {
	if got := (Technique{ID: "T1190"}).URL(); got != "https://attack.mitre.org/techniques/T1190/" {
		t.Errorf("URL = %q", got)
	}
	// Sub-techniques use a nested path.
	if got := (Technique{ID: "T1078.004"}).URL(); got != "https://attack.mitre.org/techniques/T1078/004/" {
		t.Errorf("sub-technique URL = %q", got)
	}
}
