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
		ontology.EdgeExploits:      {"T1190", "TA0001"},
		ontology.EdgeConnectsTo:    {"T1021", "TA0008"},
		ontology.EdgeCanEscalateTo: {"T1098.003", "TA0004"},
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
	// A library that has a CVE and an image that ships a library are facts about software,
	// not adversary actions: they used to read as Initial Access and Supply Chain Compromise.
	for _, e := range []ontology.EdgeType{ontology.EdgeHosts, ontology.EdgeBuiltFrom, ontology.EdgeCompiledInto, ontology.EdgeMitigates,
		ontology.EdgeAffects, ontology.EdgeDependsOn} {
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

// Initial access is credited to the hop where access is gained, and an exploit once the
// attacker is inside is lateral movement.
func TestForStepReadsTheRoute(t *testing.T) {
	log4shell := []ontology.EdgeType{ontology.EdgeExposes, ontology.EdgeHosts, ontology.EdgeDependsOn,
		ontology.EdgeAffects, ontology.EdgeExploits}
	want := []string{"", "", "", "", "T1190"}
	for i, id := range want {
		tech, ok := ForStep(log4shell, i)
		if (id == "") == ok || tech.ID != id {
			t.Errorf("log4shell hop %d (%s): %q ok=%v, want %q", i, log4shell[i], tech.ID, ok, id)
		}
	}
	// No exploit on the route: the exposure is where access is gained.
	if tech, ok := ForStep([]ontology.EdgeType{ontology.EdgeExposes, ontology.EdgeHasPermission}, 0); !ok || tech.ID != "T1190" {
		t.Errorf("exposure without an exploit: %q ok=%v, want T1190", tech.ID, ok)
	}
	// An exploit reached after lateral movement is exploitation of a remote service.
	lateral := []ontology.EdgeType{ontology.EdgeExposes, ontology.EdgeConnectsTo, ontology.EdgeAffects, ontology.EdgeExploits}
	if tech, ok := ForStep(lateral, 3); !ok || tech.ID != "T1210" || tech.Tactic != "Lateral Movement" {
		t.Errorf("exploit after lateral movement: %+v ok=%v, want T1210", tech, ok)
	}
	if tech, ok := ForStep(lateral, 0); !ok || tech.ID != "T1190" {
		t.Errorf("the exposure before a LATERAL exploit is still the way in: %q ok=%v", tech.ID, ok)
	}
	if _, ok := ForStep(lateral, 9); ok {
		t.Error("an index past the route has no technique")
	}
}
