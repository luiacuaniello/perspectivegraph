package redteam

import (
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// assertionsFor translates a scored attack path into the ordered claims the oracle
// must settle, one per hop. The mapping is deliberately conservative: only hops an
// API oracle can actually check are marked Testable, so a path built partly on a CVE
// exploit (which no policy simulator can settle) can never be reported CONFIRMED on
// the identity/network hops alone.
func assertionsFor(p analyzer.AttackPath) []Assertion {
	out := make([]Assertion, 0, len(p.Steps))
	for _, st := range p.Steps {
		out = append(out, assertionForStep(st))
	}
	return out
}

// assertionForStep maps one hop to the claim about reality it asserts. The claim is
// keyed by node id (From/Resource): the live oracle resolves those to ARNs from the
// same graph the path came from.
func assertionForStep(st analyzer.Step) Assertion {
	switch st.EdgeType {
	case ontology.EdgeAssumes:
		// instance --ASSUMES--> role: the IMDS hop. Reality check = can this principal
		// actually obtain the role's credentials (sts:AssumeRole succeeds, or IMDS
		// returns creds), which IMDSv2 posture and the role trust policy decide.
		return Assertion{Kind: KindIAM, Principal: st.From, Action: "sts:AssumeRole", Resource: st.To,
			Testable: true, Note: "assume the target role's credentials"}
	case ontology.EdgeCanEscalateTo:
		// principal --CAN_ESCALATE_TO--> account-admin: the privilege-escalation claim.
		// Reality check = SimulatePrincipalPolicy on the principal for the escalation's
		// action(s), which honors SCPs, boundaries and conditions the engine skips.
		return Assertion{Kind: KindIAM, Principal: st.From, Action: "iam:*", Resource: st.To,
			Testable: true, Note: "escalate to admin-equivalent privileges"}
	case ontology.EdgeHasPermission:
		return Assertion{Kind: KindIAM, Principal: st.From, Action: "iam:*", Resource: st.To,
			Testable: true, Note: "exercise the granted permission"}
	case ontology.EdgeConnectsTo, ontology.EdgeExposes, ontology.EdgeRoutesTo:
		// Network reachability: a bounded TCP dial from an in-VPC probe host settles
		// whether the traffic the engine inferred from SG/route/NACL actually flows.
		return Assertion{Kind: KindNetwork, Principal: st.From, Action: "tcp:connect", Resource: st.To,
			Testable: true, Note: "open a connection along the inferred reachability"}
	case ontology.EdgeExploits, ontology.EdgeAffects:
		// A vulnerability exploit: no API oracle can settle this without a real exploit
		// attempt, so it stays inconclusive and blocks a CONFIRMED verdict end-to-end.
		return Assertion{Kind: KindExploit, Principal: st.From, Action: "cve:exploit", Resource: st.To,
			Testable: false, Note: "requires a real exploit attempt; no API oracle"}
	default:
		return Assertion{Kind: KindExploit, Principal: st.From, Resource: st.To,
			Testable: false, Note: "no oracle mapping for this edge type"}
	}
}
