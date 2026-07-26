package redteam

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

var clock = time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)

const roleARN = "arn:aws:iam::111111111111:role/ec2-role"

func ssrfPath() analyzer.AttackPath { return ssrfPathFor(roleARN) }

// ssrfPathFor is the ec2_ssrf shape: internet EC2 --ASSUMES--> role --CAN_ESCALATE_TO-->
// admin. The role carries its ARN the way the IAM collector records it; the instance
// and the synthetic admin node have none, which is what the real graph looks like.
func ssrfPathFor(arn string) analyzer.AttackPath {
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "vm", Label: ontology.LabelVirtualMachine, Name: "ec2-app",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "ec2-role",
				Properties: map[string]any{ontology.PropARN: arn}},
			{ID: "admin", Label: ontology.LabelIAMRole, Name: "account-admin",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeAssumes, From: "vm", To: "role", ExploitProbability: 0.9},
			{Type: ontology.EdgeCanEscalateTo, From: "role", To: "admin", ExploitProbability: 0.9},
		},
	}
	paths := analyzer.FindCriticalPaths(snap)
	if len(paths) != 1 {
		panic(fmt.Sprintf("fixture expected 1 path, got %d", len(paths)))
	}
	return paths[0]
}

// fakeIAM answers a fixed decision per action, so the oracle's whole decision path is
// exercised without an AWS account.
type fakeIAM struct {
	decisions map[string]iamtypes.PolicyEvaluationDecisionType
	asked     []string
	err       error
}

func (f *fakeIAM) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := &iam.SimulatePrincipalPolicyOutput{}
	for _, act := range in.ActionNames {
		f.asked = append(f.asked, act)
		d, ok := f.decisions[act]
		if !ok {
			d = iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
		}
		out.EvaluationResults = append(out.EvaluationResults, iamtypes.EvaluationResult{
			EvalActionName: aws.String(act), EvalDecision: d,
		})
	}
	return out, nil
}

func allow(actions ...string) *fakeIAM {
	m := map[string]iamtypes.PolicyEvaluationDecisionType{}
	for _, a := range actions {
		m[a] = iamtypes.PolicyEvaluationDecisionTypeAllowed
	}
	return &fakeIAM{decisions: m}
}

// ── assertion mapping ───────────────────────────────────────────────────────

func TestAssertionsResolveARNsNotGraphIDs(t *testing.T) {
	as := assertionsFor(ssrfPath())
	if len(as) != 2 {
		t.Fatalf("expected 2 assertions, got %d", len(as))
	}

	// The escalation hop acts as the role, so it carries the role's ARN - reality
	// cannot answer a question about a content-hashed graph id.
	esc := as[1]
	if esc.Principal != roleARN {
		t.Errorf("escalation principal = %q, want the role ARN", esc.Principal)
	}
	if !esc.Testable {
		t.Error("an escalation from a principal with an ARN must be checkable")
	}
	if esc.Action == "iam:*" {
		t.Error("the escalation assertion must not carry iam:*, which AWS reads as 'every IAM action'")
	}

	// The ASSUMES hop acts as the instance, which has no ARN of its own, so it is
	// honestly not settleable rather than asked about a hash.
	if as[0].Testable {
		t.Error("an ASSUMES hop from a node with no ARN must not be marked testable")
	}
}

func TestUntestableHopIsNotConfirmable(t *testing.T) {
	a := assertionForStep(
		analyzer.Step{EdgeType: ontology.EdgeExploits, From: "cve", To: "role"},
		ontology.Node{ID: "cve"}, ontology.Node{ID: "role"},
	)
	if a.Testable {
		t.Error("a CVE-exploit hop must not be testable")
	}
}

// ── the AWS oracle ──────────────────────────────────────────────────────────

// The regression that matters most: asking AWS about "iam:*" means "may perform EVERY
// IAM action", so a principal holding one genuine privesc permission would come back
// denied and be recorded as a REFUTED verdict. That is a false outcome fed straight
// into the calibration dataset - worse than having no oracle at all.
func TestEscalationNeverAsksForWildcardIAM(t *testing.T) {
	f := allow("iam:AttachUserPolicy")
	res, err := NewAWSOracle(f).Check(context.Background(), assertionsFor(ssrfPath())[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, act := range f.asked {
		if strings.Contains(act, "*") {
			t.Errorf("oracle asked AWS about wildcard action %q", act)
		}
	}
	if res.Decision != Allowed {
		t.Errorf("a principal holding iam:AttachUserPolicy escalates; got %s (%s)", res.Decision, res.Evidence)
	}
	if !strings.Contains(res.Evidence, "AttachUserPolicy") {
		t.Errorf("evidence should name the primitive that held, got %q", res.Evidence)
	}
}

// A primitive needing two actions holds only when BOTH are permitted - the same
// all-of rule the detector applies, so the oracle grades the engine on what it
// actually claims.
func TestEscalationRequiresEveryActionOfAPrimitive(t *testing.T) {
	esc := assertionsFor(ssrfPath())[1]

	half, err := NewAWSOracle(allow("iam:PassRole")).Check(context.Background(), esc)
	if err != nil {
		t.Fatal(err)
	}
	if half.Decision != Denied {
		t.Errorf("iam:PassRole alone is not an escalation; got %s", half.Decision)
	}

	both, err := NewAWSOracle(allow("iam:PassRole", "lambda:CreateFunction")).Check(context.Background(), esc)
	if err != nil {
		t.Fatal(err)
	}
	if both.Decision != Allowed {
		t.Errorf("PassRole + lambda:CreateFunction is a known primitive; got %s (%s)", both.Decision, both.Evidence)
	}
}

// This is the verdict the flywheel cannot get any other honest way: the engine
// surfaced an escalation, and AWS - which evaluates the SCPs and condition keys the
// engine skips - says no.
func TestEscalationDeniedByAWSIsARefutation(t *testing.T) {
	res, err := NewAWSOracle(allow()).Check(context.Background(), assertionsFor(ssrfPath())[1])
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != Denied {
		t.Fatalf("no permitted primitive must refute the claim, got %s", res.Decision)
	}
	if !strings.Contains(res.Evidence, "none of the") {
		t.Errorf("evidence should say nothing was permitted, got %q", res.Evidence)
	}
}

// A failed question is not a refutation. If the call errors - throttling, a bad ARN,
// a missing simulate permission - the oracle must stay silent rather than manufacture
// evidence against the engine.
func TestOracleFailureIsInconclusiveNotDenied(t *testing.T) {
	f := &fakeIAM{err: fmt.Errorf("AccessDenied: not authorized to perform iam:SimulatePrincipalPolicy")}
	res, err := NewAWSOracle(f).Check(context.Background(), assertionsFor(ssrfPath())[1])
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != Inconclusive {
		t.Errorf("a failed simulation must be inconclusive, got %s", res.Decision)
	}
}

func TestUnconfiguredOracleIsInert(t *testing.T) {
	rec, err := Attempt(context.Background(), NewAWSOracle(nil), ssrfPath(), "t1", clock)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != validation.Partial {
		t.Errorf("an unconfigured oracle must yield partial, got %s", rec.Outcome)
	}
}

// ── the runner ──────────────────────────────────────────────────────────────

func TestAttemptRefutesWhenRealityDenies(t *testing.T) {
	esc := assertionsFor(ssrfPath())[1]
	o := NewFixtureOracle(map[string]Result{
		esc.Key(): {Decision: Denied, Evidence: "permission boundary caps iam:*"},
	}, Allowed)

	rec, err := Attempt(context.Background(), o, ssrfPath(), "t1", clock)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != validation.Refuted {
		t.Fatalf("outcome = %s, want refuted", rec.Outcome)
	}
	if rec.PredictedScore == 0 {
		t.Error("a refuted verdict still needs the predicted score it refutes")
	}
	if !strings.Contains(rec.Evidence, "permission boundary") {
		t.Errorf("evidence should cite the denial, got %q", rec.Evidence)
	}
}

// An internet-origin path contains a hop no policy oracle can settle - whether an
// attacker gets code execution on the exposed host - so it is never Confirmed. Feeding
// those Partial verdicts to the store would enter them as the label 0.5 and pull the
// observed rate to 0.30, reporting the engine as badly overconfident purely because the
// oracle could not ask. CalibrationGrade is what keeps that out of the dataset.
func TestUnsettledVerdictsAreNotCalibrationEvidence(t *testing.T) {
	rec, err := Attempt(context.Background(), NewFixtureOracle(nil, Allowed), ssrfPath(), "t1", clock)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != validation.Partial {
		t.Fatalf("an unsettleable code-execution hop must yield partial, got %s", rec.Outcome)
	}
	if CalibrationGrade(rec) {
		t.Error("a partial verdict must not be admissible as calibration evidence")
	}

	// Show what admitting it would have done, so the guard's value is measured rather
	// than asserted.
	contaminated, err := validation.New("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		r := rec
		r.PathID = fmt.Sprintf("ap-%02d", i)
		if _, err := contaminated.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	cal := contaminated.Calibration("t1")
	if cal.ObservedRate > 0.55 {
		t.Fatalf("expected the contaminated set to read low, got %.2f", cal.ObservedRate)
	}
	t.Logf("guard justified: admitting unsettled verdicts would report observed %.2f vs predicted %.2f (verdict %q)",
		cal.ObservedRate, cal.MeanPredicted, cal.Verdict)
}

// A refutation IS admissible: reality was asked and said no.
func TestRefutationIsCalibrationEvidence(t *testing.T) {
	esc := assertionsFor(ssrfPath())[1]
	o := NewFixtureOracle(map[string]Result{
		esc.Key(): {Decision: Denied, Evidence: "permission boundary blocks every primitive"},
	}, Allowed)

	rec, err := Attempt(context.Background(), o, ssrfPath(), "t1", clock)
	if err != nil {
		t.Fatal(err)
	}
	if !CalibrationGrade(rec) {
		t.Fatalf("a refuted verdict is real evidence; outcome was %s", rec.Outcome)
	}
}

// TestEscalationAuditIsTheUncensoredMeasurement is the honest calibration product: the
// escalation claim is one AWS answers BOTH ways, so precision over it is a real number
// rather than an artefact of what the oracle can observe.
func TestEscalationAuditIsTheUncensoredMeasurement(t *testing.T) {
	// Ten DIFFERENT principals: an assertion is keyed by principal and action, not by
	// path, because reality's answer does not depend on which path prompted the
	// question. Ten paths through one role are one question, not ten.
	paths := make([]analyzer.AttackPath, 0, 10)
	for i := 0; i < 10; i++ {
		p := ssrfPathFor(fmt.Sprintf("arn:aws:iam::111111111111:role/app-%02d", i))
		p.ID = fmt.Sprintf("ap-%02d", i)
		paths = append(paths, p)
	}

	// Reality upholds 6 of the 10 escalation claims and blocks 4.
	decisions := map[string]Result{}
	for i, p := range paths {
		d := Result{Decision: Allowed, Evidence: "holds iam:AttachUserPolicy"}
		if i < 4 {
			d = Result{Decision: Denied, Evidence: "permission boundary caps iam:AttachUserPolicy"}
		}
		decisions[assertionsFor(p)[1].Key()] = d
	}

	audit, err := AuditEscalations(context.Background(), NewFixtureOracle(decisions, Inconclusive), paths)
	if err != nil {
		t.Fatal(err)
	}
	if audit.Claims != 10 {
		t.Fatalf("claims = %d, want 10", audit.Claims)
	}
	if audit.Confirmed != 6 || audit.Refuted != 4 {
		t.Fatalf("confirmed/refuted = %d/%d, want 6/4", audit.Confirmed, audit.Refuted)
	}
	p, ok := audit.Precision()
	if !ok || p < 0.55 || p > 0.65 {
		t.Errorf("precision = %.2f (ok=%v), want ~0.60", p, ok)
	}
	if len(audit.Findings) != 4 {
		t.Errorf("every refutation needs its evidence recorded, got %d of 4", len(audit.Findings))
	}
	t.Logf("%s", audit.Summary())
}

// Precision with an empty denominator must not read as 0.00 or 1.00.
func TestPrecisionUndefinedWithoutCoverage(t *testing.T) {
	audit, err := AuditEscalations(context.Background(), NewAWSOracle(nil), []analyzer.AttackPath{ssrfPath()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := audit.Precision(); ok {
		t.Error("precision must be undefined when nothing was settled")
	}
	if audit.Unsettled != 1 {
		t.Errorf("unsettled = %d, want 1", audit.Unsettled)
	}
}

// ── the fixture oracle ──────────────────────────────────────────────────────

func TestLoadFixtureOracle(t *testing.T) {
	o, err := LoadFixtureOracle("testdata/lab-run.json")
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := o.Check(context.Background(), Assertion{Kind: KindIAM, Principal: "x", Action: "sts:AssumeRole", Resource: "y"})
	if fb.Decision != Allowed {
		t.Errorf("fallback = %s, want allowed", fb.Decision)
	}
}

func TestFixtureRejectsUnknownDecision(t *testing.T) {
	var r Result
	if err := r.UnmarshalJSON([]byte(`"maybe"`)); err == nil {
		t.Error("an unknown decision string must fail loudly, not default to allowed")
	}
}
