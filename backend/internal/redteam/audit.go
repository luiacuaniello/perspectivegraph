package redteam

import (
	"context"
	"fmt"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
)

// EscalationAudit is what a policy oracle can honestly measure, and it is deliberately
// NOT a path score.
//
// Path-level verdicts from this oracle are one-sided. Every internet-origin path
// contains a hop no API can settle - whether an attacker gets code execution on the
// exposed host - so such a path can be Refuted but never Confirmed. A calibration set
// built from those verdicts is censored: it can only ever contain the outcome 0, the
// observed rate collapses to zero, and rescaling on it would drive every score to the
// floor. That is not a measurement, it is an artefact of what the instrument can see.
//
// The escalation claim is different. "This principal holds a privilege-escalation
// primitive" is a claim AWS answers both ways, on demand, for free, applying the SCPs
// and condition keys the engine's own evaluator skips. Both outcomes are observable,
// so the sample is uncensored and the resulting precision is a real number about a
// real weakness in the engine.
//
// So: use this to answer "how often is the engine's privesc detection right?", and use
// [Attempt] for the audit trail and for individual refutations. Do not use either to
// rescale S(P) - that needs exploited outcomes, which no dry run provides.
type EscalationAudit struct {
	// Claims is how many escalation hops the engine asserted across the paths.
	Claims int
	// Confirmed and Refuted are the settled verdicts. Refuted is the interesting one:
	// the engine said a principal could escalate and AWS says it cannot.
	Confirmed int
	Refuted   int
	// Unsettled counts claims the oracle could not put to AWS at all - a principal with
	// no ARN in the graph, or a failed simulation. Reported rather than folded into the
	// denominator, because coverage is part of the result.
	Unsettled int
	// Findings records each refutation with the evidence, so a precision number below 1
	// can be inspected instead of merely believed.
	Findings []EscalationFinding
}

// EscalationFinding is one refuted escalation claim: the engine's belief, and reality's
// answer.
type EscalationFinding struct {
	PathID    string
	Principal string
	Evidence  string
}

// Precision is Confirmed / (Confirmed + Refuted) - the share of settled escalation
// claims that reality upheld. It returns ok=false when nothing was settled, rather
// than a misleading 0 or 1 from an empty denominator.
func (a EscalationAudit) Precision() (float64, bool) {
	settled := a.Confirmed + a.Refuted
	if settled == 0 {
		return 0, false
	}
	return float64(a.Confirmed) / float64(settled), true
}

// Coverage is the share of escalation claims the oracle managed to settle. A precision
// of 1.00 over 5% coverage says almost nothing, so the two travel together.
func (a EscalationAudit) Coverage() (float64, bool) {
	if a.Claims == 0 {
		return 0, false
	}
	return float64(a.Confirmed+a.Refuted) / float64(a.Claims), true
}

// Summary renders the audit as one auditable line, with coverage always alongside
// precision so the number cannot be quoted without its denominator.
func (a EscalationAudit) Summary() string {
	p, okP := a.Precision()
	c, _ := a.Coverage()
	if !okP {
		return fmt.Sprintf("0 of %d escalation claims settled (no coverage; precision undefined)", a.Claims)
	}
	return fmt.Sprintf("escalation precision %.2f (%d upheld, %d refuted) over %.0f%% coverage of %d claims",
		p, a.Confirmed, a.Refuted, c*100, a.Claims)
}

// AuditEscalations asks the oracle to settle every escalation claim in the given paths.
// It performs no writes and, with the AWS oracle, no state changes of any kind: each
// check is one `iam:SimulatePrincipalPolicy` dry run.
func AuditEscalations(ctx context.Context, o Oracle, paths []analyzer.AttackPath) (EscalationAudit, error) {
	var audit EscalationAudit
	for _, p := range paths {
		for _, a := range assertionsFor(p) {
			if a.Action != escalationAction {
				continue
			}
			audit.Claims++
			if !a.Testable {
				audit.Unsettled++
				continue
			}
			res, err := o.Check(ctx, a)
			if err != nil {
				return EscalationAudit{}, fmt.Errorf("oracle check %s: %w", a.Key(), err)
			}
			switch res.Decision {
			case Allowed:
				audit.Confirmed++
			case Denied:
				audit.Refuted++
				audit.Findings = append(audit.Findings, EscalationFinding{
					PathID: p.ID, Principal: a.Principal, Evidence: res.Evidence,
				})
			default:
				audit.Unsettled++
			}
		}
	}
	return audit, nil
}
