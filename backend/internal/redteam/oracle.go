// Package redteam turns the engine's attack paths into empirical calibration
// evidence by ATTEMPTING them and recording what reality allows.
//
// The calibration flywheel (internal/validation) needs `refuted` verdicts: paths the
// engine surfaced that fail when actually attacked. Generating those honestly is the
// hard part, because the engine's per-edge probabilities encode the author's beliefs.
// If we ALSO decide which paths are real, the loop is circular and the resulting
// calibration measures only how well the engine agrees with itself - a flattering
// number that means nothing.
//
// So the verdict must come from an oracle INDEPENDENT of the engine: reality.
//   - IAM claims    -> iam:SimulatePrincipalPolicy, AWS's own authoritative policy
//     evaluator, or an actual sts:AssumeRole (credentials or an error).
//   - network claims -> a bounded TCP dial from an in-VPC probe host.
//   - exploit claims -> not settleable by an API oracle; left inconclusive.
//
// Whatever the engine believed, AWS answers. That independence is what turns a verdict
// into evidence rather than a restatement of the model.
//
// This file defines the oracle contract. The path->verdict runner (runner.go) and the
// deterministic fixture oracle (fixture_oracle.go) make the whole harness testable
// with no AWS account; the live oracle (aws_oracle.go) is inert until wired, and the
// randomized lab that feeds it lives in deploy/redteam-lab. Nothing here touches AWS.
package redteam

import "context"

// Decision is reality's answer to whether one attack step actually works. The zero
// value is Inconclusive on purpose: an oracle that cannot decide must never be read
// as a refutation, so an untestable or unreachable hop can't manufacture evidence.
type Decision int

const (
	Inconclusive Decision = iota // the oracle could not settle the claim
	Allowed                      // reality permits the action / the probe succeeds
	Denied                       // reality refuses it - the engine surfaced a step that does not work
)

func (d Decision) String() string {
	switch d {
	case Allowed:
		return "allowed"
	case Denied:
		return "denied"
	default:
		return "inconclusive"
	}
}

// AssertionKind is the class of claim a hop makes, which decides how the oracle
// settles it.
type AssertionKind string

const (
	KindIAM     AssertionKind = "iam"     // a principal may perform an action (SimulatePrincipalPolicy / AssumeRole)
	KindNetwork AssertionKind = "network" // one host can reach another (TCP probe)
	KindExploit AssertionKind = "exploit" // a vulnerability is exploitable (no API oracle)
)

// Assertion is the concrete, independently-checkable claim a single path hop makes
// about reality: "principal X may perform action A on resource R", or "host X can
// open a connection to host Y". The oracle answers it by asking reality, never by
// consulting the engine's probabilities.
type Assertion struct {
	Kind      AssertionKind `json:"kind"`
	Principal string        `json:"principal"`          // the acting node (ARN or graph id)
	Action    string        `json:"action,omitempty"`   // e.g. "sts:AssumeRole", "iam:*"
	Resource  string        `json:"resource,omitempty"` // the target node
	Note      string        `json:"note,omitempty"`     // human description of the claim
	// Testable is false for claims no API oracle can settle (a CVE exploit). The runner
	// counts those as inconclusive rather than pretending a verdict, so a path is only
	// ever CONFIRMED when every one of its hops was actually checkable and allowed.
	Testable bool `json:"testable"`
}

// Key is the stable identity of an assertion, used to look up a fixture decision and
// to deduplicate. It is intentionally independent of Note/Testable (presentation).
func (a Assertion) Key() string {
	return string(a.Kind) + "|" + a.Principal + "|" + a.Action + "|" + a.Resource
}

// Result is an oracle's answer to one assertion, with the evidence that justifies it
// (an AWS error code, a SimulatePrincipalPolicy decision, a dial outcome) so a human
// can audit why a path was confirmed or refuted.
type Result struct {
	Decision Decision `json:"decision"`
	Evidence string   `json:"evidence,omitempty"`
}

// Oracle settles a single assertion against reality. Implementations MUST be
// independent of the engine's scoring, and MUST return Inconclusive (never Denied)
// when they cannot decide, so an untestable or unreachable hop never fabricates a
// refutation. Check should honor ctx for cancellation/timeouts.
type Oracle interface {
	Check(ctx context.Context, a Assertion) (Result, error)
}
