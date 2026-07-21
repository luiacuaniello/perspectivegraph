package redteam

import "context"

// AWSOracle is the live oracle: it settles assertions against AWS itself, the only
// authority independent of the engine's beliefs. It is INERT in this skeleton -
// Check always returns Inconclusive - so the harness can never fabricate a verdict
// before the real wiring exists. An inert oracle yields only Partial verdicts, which
// carry no calibration signal, so an accidental run pollutes nothing.
//
// Wiring is a localized change, one branch per assertion kind, each using a source of
// truth that does NOT consult the engine:
//
//	KindIAM (action)   -> iam:SimulatePrincipalPolicy(principal, action): AWS's own
//	                      authoritative evaluator. It honors SCPs, permission
//	                      boundaries and condition keys that the engine deliberately
//	                      skips - which is precisely why it can DENY a path the engine
//	                      surfaced, producing the refuted verdicts calibration needs.
//	KindIAM (AssumeRole) -> sts:AssumeRole against the target role: credentials
//	                      returned = Allowed, an AccessDenied error = Denied.
//	KindNetwork        -> a bounded TCP dial from an in-VPC probe host to the target,
//	                      settling whether the SG/route/NACL-inferred reachability
//	                      actually carries traffic.
//	KindExploit        -> out of scope for an API oracle; stays Inconclusive.
//
// The live oracle must run ONLY against a dedicated, disposable lab account (see
// deploy/redteam-lab), never anything real: it exercises admin-equivalent escalations
// to observe whether AWS permits them.
type AWSOracle struct {
	// ready gates any real call. It stays false until a constructor wires the AWS
	// clients AND the operator has explicitly opted into a lab account, so the zero
	// value is safe and inert.
	ready bool
}

// NewAWSOracle returns the inert live oracle. It intentionally does not accept AWS
// clients yet: wiring them (and flipping ready) is the step that first touches AWS,
// kept out of the skeleton on purpose.
func NewAWSOracle() *AWSOracle { return &AWSOracle{} }

// Check settles an assertion against AWS. While inert it returns Inconclusive for
// everything, so no path is ever confirmed or refuted from a live oracle that has not
// been wired to a lab account.
func (o *AWSOracle) Check(_ context.Context, a Assertion) (Result, error) {
	if !o.ready {
		return Result{Decision: Inconclusive, Evidence: "aws oracle not wired (skeleton); see aws_oracle.go"}, nil
	}
	// Wiring goes here: dispatch on a.Kind to SimulatePrincipalPolicy / sts:AssumeRole
	// / a TCP probe. Left unimplemented so the skeleton cannot reach AWS.
	return Result{Decision: Inconclusive, Evidence: "no oracle implementation for " + string(a.Kind)}, nil
}
