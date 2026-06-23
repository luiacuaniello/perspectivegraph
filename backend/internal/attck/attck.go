// Package attck maps PerspectiveGraph's ontology edge types to MITRE ATT&CK
// techniques, so each hop of an attack path is labelled with the adversary
// technique (and tactic) it represents - turning a probability-ranked route into
// a recognizable kill chain a defender can map to detections and controls.
//
// The mapping is a documented best-fit heuristic, consistent with the rest of the
// tool's honesty about evidence vs. estimate: it is informational context, not a
// claim that the technique was observed. Structural/build/defensive edges (HOSTS,
// BUILT_FROM, COMPILED_INTO, MITIGATES) carry no technique.
package attck

import (
	"strings"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Technique is one MITRE ATT&CK technique and the tactic it serves.
type Technique struct {
	ID       string // e.g. "T1190" or the sub-technique "T1078.004"
	Name     string
	Tactic   string // human-readable tactic, e.g. "Initial Access"
	TacticID string // e.g. "TA0001"
}

// URL is the canonical MITRE ATT&CK page for the technique.
func (t Technique) URL() string {
	return "https://attack.mitre.org/techniques/" + strings.Replace(t.ID, ".", "/", 1) + "/"
}

// byEdge is the heuristic edge-type → technique mapping.
var byEdge = map[ontology.EdgeType]Technique{
	// Reaching / exploiting an exposed service → Initial Access.
	ontology.EdgeExposes:  {"T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"},
	ontology.EdgeRoutesTo: {"T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"},
	ontology.EdgeAffects:  {"T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"},
	ontology.EdgeExploits: {"T1203", "Exploitation for Client Execution", "Execution", "TA0002"},
	// A vulnerable dependency riding in the image → supply-chain initial access.
	ontology.EdgeDependsOn: {"T1195.002", "Compromise Software Supply Chain", "Initial Access", "TA0001"},
	// Network reachability between assets → Lateral Movement.
	ontology.EdgeConnectsTo: {"T1021", "Remote Services", "Lateral Movement", "TA0008"},
	// Identity assuming a role / using a permission → Valid Accounts.
	ontology.EdgeAssumes:       {"T1078", "Valid Accounts", "Privilege Escalation", "TA0004"},
	ontology.EdgeHasPermission: {"T1078", "Valid Accounts", "Privilege Escalation", "TA0004"},
	ontology.EdgeCanEscalateTo: {"T1078.004", "Valid Accounts: Cloud Accounts", "Privilege Escalation", "TA0004"},
	ontology.EdgeAuthenticates: {"T1078", "Valid Accounts", "Initial Access", "TA0001"},
	// Breaking out of a container to the host/node.
	ontology.EdgeEscapesTo: {"T1611", "Escape to Host", "Privilege Escalation", "TA0004"},
}

// ForEdge returns the ATT&CK technique for an edge type. ok is false for
// structural/defensive edges that don't represent an adversary action.
func ForEdge(t ontology.EdgeType) (Technique, bool) {
	tech, ok := byEdge[t]
	return tech, ok
}
