package redteam

import (
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// assertionsFor translates a scored attack path into the ordered claims the oracle
// must settle, one per hop. The mapping is deliberately conservative: only hops an
// API oracle can actually check are marked Testable, so a path built partly on a CVE
// exploit (which no policy simulator can settle) can never be reported CONFIRMED on
// the identity/network hops alone.
//
// Hops are resolved against the path's NODES, not just its steps, because a step
// carries graph ids and a graph id is a content hash - `IAM_Role:9f2b…`, not an ARN.
// Reality does not answer questions about hashes: an IAM claim is only checkable if
// the node carries the ARN the principal actually has.
func assertionsFor(p analyzer.AttackPath) []Assertion {
	byID := make(map[string]ontology.Node, len(p.Nodes))
	for _, n := range p.Nodes {
		byID[n.ID] = n
	}
	out := make([]Assertion, 0, len(p.Steps))
	for _, st := range p.Steps {
		out = append(out, assertionForStep(st, byID[st.From], byID[st.To]))
	}
	return out
}

// arnOf returns a node's cloud ARN, or "" when it has none (a synthetic node such as
// the account-admin target, or a feed that never carried one).
func arnOf(n ontology.Node) string {
	if s, ok := n.Properties[ontology.PropARN].(string); ok {
		return s
	}
	return ""
}

// isIAMPrincipal reports whether an ARN can act as a policy-simulation source. AWS
// accepts only a user, group or role there - an EC2 instance ARN is rejected outright.
// So a hop whose acting side is a machine is genuinely unsettleable by a policy oracle,
// and saying so up front beats sending a request that is certain to fail.
func isIAMPrincipal(arn string) bool {
	if !strings.HasPrefix(arn, "arn:") || !strings.Contains(arn, ":iam:") {
		return false
	}
	for _, kind := range []string{":role/", ":user/", ":group/"} {
		if strings.Contains(arn, kind) {
			return true
		}
	}
	return false
}

// assertionForStep maps one hop to the claim about reality it asserts.
func assertionForStep(st analyzer.Step, from, to ontology.Node) Assertion {
	fromARN, toARN := arnOf(from), arnOf(to)

	switch st.EdgeType {
	case ontology.EdgeAssumes:
		// instance --ASSUMES--> role: the IMDS hop. Reality check = may this principal
		// actually obtain the role's credentials, which the role's trust policy decides.
		// The acting side is often an instance with no ARN of its own, so the claim is
		// only checkable when both ends resolve.
		return Assertion{
			Kind: KindIAM, Action: "sts:AssumeRole",
			Principal: coalesce(fromARN, st.From), Resource: coalesce(toARN, st.To),
			Testable: isIAMPrincipal(fromARN) && toARN != "",
			Note:     "assume the target role's credentials",
		}

	case ontology.EdgeCanEscalateTo, ontology.EdgeHasPermission:
		// principal --CAN_ESCALATE_TO--> account-admin. The target is the engine's own
		// synthetic admin node and has no ARN, so only the acting principal must
		// resolve. The actions come from the shared privesc table at check time - the
		// claim is "this principal holds SOME escalation primitive", never the literal
		// action "iam:*", which AWS reads as "may do everything in IAM" and would
		// refute a principal holding a single, genuine privesc permission.
		return Assertion{
			Kind: KindIAM, Action: escalationAction,
			Principal: coalesce(fromARN, st.From), Resource: coalesce(toARN, st.To),
			Testable: isIAMPrincipal(fromARN),
			Note:     "hold at least one privilege-escalation primitive",
		}

	case ontology.EdgeConnectsTo, ontology.EdgeExposes, ontology.EdgeRoutesTo:
		// Network reachability: settling this needs a bounded TCP dial from an in-VPC
		// probe host, which is infrastructure this harness does not stand up. Left
		// unchecked rather than guessed.
		return Assertion{
			Kind: KindNetwork, Action: "tcp:connect", Principal: st.From, Resource: st.To,
			Testable: false,
			Note:     "requires an in-VPC probe host; not settled by an API oracle",
		}

	default:
		// A vulnerability exploit: no API oracle can settle this without a real exploit
		// attempt, so it stays inconclusive and blocks a CONFIRMED verdict end-to-end.
		return Assertion{
			Kind: KindExploit, Action: "cve:exploit", Principal: st.From, Resource: st.To,
			Testable: false,
			Note:     "requires a real exploit attempt; no API oracle",
		}
	}
}

// escalationAction is the sentinel action for "holds some privesc primitive". It is
// not an IAM action name and must never be sent to AWS as one - the oracle expands it
// into the concrete primitives instead.
const escalationAction = "privesc:any"

// EscalationClaim builds the claim "this principal holds at least one
// privilege-escalation primitive" for a principal named by ARN, so a caller can settle
// it directly without an attack path in hand. The sentinel action stays unexported:
// callers cannot accidentally construct a claim that sends "iam:*" to AWS.
//
// The claim is untestable, and so never settled, unless the ARN names an IAM user,
// group or role - the only things AWS accepts as a simulation source.
func EscalationClaim(principalARN string) Assertion {
	return EscalationClaimOn(principalARN, "")
}

// EscalationClaimOn narrows the claim to a single resource: "could this principal
// escalate *by acting on this thing*".
//
// It exists because the unscoped question is account-wide. AWS evaluates a simulation
// with no resource named against `*`, so a grant confined to specific resources answers
// `implicitDeny` there - indistinguishable from holding no grant at all. The engine does
// surface those grants (scored down as `resource_scoped`), so settling one means naming
// the resource it covers.
//
// Pass the ARN of the thing the grant is scoped to - the user a policy could be attached
// to, the role that could be passed. An empty or non-ARN resource leaves the claim
// account-wide.
func EscalationClaimOn(principalARN, resourceARN string) Assertion {
	resource := "account-admin"
	note := "hold at least one privilege-escalation primitive"
	if strings.HasPrefix(resourceARN, "arn:") {
		resource = resourceARN
		note = "hold at least one privilege-escalation primitive over " + resourceARN
	}
	return Assertion{
		Kind: KindIAM, Action: escalationAction,
		Principal: principalARN, Resource: resource,
		Testable: isIAMPrincipal(principalARN),
		Note:     note,
	}
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
