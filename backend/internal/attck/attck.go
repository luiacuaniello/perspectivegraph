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

// Techniques the mapping below and ForStep share.
var (
	exploitPublicFacing = Technique{"T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001"}
	exploitRemote       = Technique{"T1210", "Exploitation of Remote Services", "Lateral Movement", "TA0008"}
)

// byEdge is the heuristic edge-type → technique mapping, for an edge seen on its own.
//
// Only edges that are something an attacker DOES carry a technique. A library that has a
// CVE (AFFECTS) and an image that ships a library (DEPENDS_ON) are facts about the
// software, not steps an adversary takes: they used to read "T1190 · Initial Access" and
// "T1195.002 · Supply Chain Compromise", which a practitioner reads as a mapping nobody
// checked - and then trusts nothing else on the page.
var byEdge = map[ontology.EdgeType]Technique{
	// Reaching a service the internet can reach; the exploit, when there is one, is where
	// access is actually gained (see ForStep).
	ontology.EdgeExposes:  exploitPublicFacing,
	ontology.EdgeRoutesTo: exploitPublicFacing,
	// Exploiting a vulnerability. Public-facing by default; ForStep makes it lateral
	// movement when the attacker is already inside.
	ontology.EdgeExploits: exploitPublicFacing,
	// Network reachability between assets → Lateral Movement.
	ontology.EdgeConnectsTo: {"T1021", "Remote Services", "Lateral Movement", "TA0008"},
	// Identity assuming a role / using a permission → Valid Accounts.
	ontology.EdgeAssumes:       {"T1078", "Valid Accounts", "Privilege Escalation", "TA0004"},
	ontology.EdgeHasPermission: {"T1078", "Valid Accounts", "Privilege Escalation", "TA0004"},
	ontology.EdgeAuthenticates: {"T1078", "Valid Accounts", "Initial Access", "TA0001"},
	// An identity granting itself more (PassRole, AttachRolePolicy, CreatePolicyVersion…):
	// the cloud IAM escalation ATT&CK files under additional cloud roles.
	ontology.EdgeCanEscalateTo: {"T1098.003", "Account Manipulation: Additional Cloud Roles", "Privilege Escalation", "TA0004"},
	// Breaking out of a container to the host/node.
	ontology.EdgeEscapesTo: {"T1611", "Escape to Host", "Privilege Escalation", "TA0004"},
}

// inside are the edges after which the attacker is past the perimeter: an exploit that
// follows one is movement between systems, not initial access.
var inside = map[ontology.EdgeType]bool{
	ontology.EdgeConnectsTo: true, ontology.EdgeAssumes: true, ontology.EdgeHasPermission: true,
	ontology.EdgeCanEscalateTo: true, ontology.EdgeEscapesTo: true, ontology.EdgeAuthenticates: true,
	ontology.EdgeExploits: true,
}

// ForStep returns the technique for hop i of a route, given the route's edge types in
// order. The same edge means different things at different places: initial access is
// credited to the hop where access is gained - the exploit when the route has one, the
// exposure otherwise - and an exploit after the attacker is already inside is lateral
// movement.
func ForStep(route []ontology.EdgeType, i int) (Technique, bool) {
	if i < 0 || i >= len(route) {
		return Technique{}, false
	}
	afterEntry := func(j int) bool {
		for _, prev := range route[:j] {
			if inside[prev] {
				return true
			}
		}
		return false
	}
	switch route[i] {
	case ontology.EdgeExploits:
		if afterEntry(i) {
			return exploitRemote, true
		}
		return exploitPublicFacing, true
	case ontology.EdgeExposes, ontology.EdgeRoutesTo:
		// The exposure is only the way in; an exploit reached before anything else
		// happens is where the access is gained, and carries the technique.
		for j := i + 1; j < len(route); j++ {
			if route[j] == ontology.EdgeExploits && !afterEntry(j) {
				return Technique{}, false
			}
		}
	}
	return ForEdge(route[i])
}

// ForEdge returns the ATT&CK technique for an edge type. ok is false for
// structural/defensive edges that don't represent an adversary action.
func ForEdge(t ontology.EdgeType) (Technique, bool) {
	tech, ok := byEdge[t]
	return tech, ok
}
