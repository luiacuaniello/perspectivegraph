package redteam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

var clock = time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)

// ssrfPath is the ec2_ssrf shape: internet EC2 --ASSUMES--> role --CAN_ESCALATE_TO-->
// admin. Both hops are IAM-testable, so a fully-allowing oracle can CONFIRM it.
func ssrfPath() analyzer.AttackPath {
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "vm", Label: ontology.LabelVirtualMachine, Name: "ec2-app",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "ec2-role"},
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

func TestAssertionMapping(t *testing.T) {
	as := assertionsFor(ssrfPath())
	if len(as) != 2 {
		t.Fatalf("expected 2 assertions, got %d", len(as))
	}
	if as[0].Kind != KindIAM || as[0].Action != "sts:AssumeRole" || !as[0].Testable {
		t.Errorf("ASSUMES hop mismapped: %+v", as[0])
	}
	if as[1].Kind != KindIAM || as[1].Action != "iam:*" || !as[1].Testable {
		t.Errorf("CAN_ESCALATE_TO hop mismapped: %+v", as[1])
	}
}

func TestUntestableHopIsNotConfirmable(t *testing.T) {
	// A CVE-exploit hop has no API oracle, so even with everything else allowed the
	// path can only be Partial - reality never signed off end-to-end.
	a := assertionForStep(analyzer.Step{EdgeType: ontology.EdgeExploits, From: "cve", To: "role"})
	if a.Testable {
		t.Error("a CVE-exploit hop must not be testable")
	}
}

func TestAttemptConfirmsWhenRealityAllows(t *testing.T) {
	o := NewFixtureOracle(nil, Allowed) // reality allows everything
	rec, err := Attempt(context.Background(), o, ssrfPath(), "t1", clock)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != validation.Confirmed {
		t.Errorf("outcome = %s, want confirmed", rec.Outcome)
	}
	if rec.PredictedScore == 0 {
		t.Error("record must carry the path's predicted score for calibration")
	}
	if rec.Source != Source || rec.Scope != validation.ScopePath {
		t.Errorf("record provenance wrong: source=%s scope=%s", rec.Source, rec.Scope)
	}
}

func TestAttemptRefutesWhenRealityDenies(t *testing.T) {
	// The escalation hop is DENIED - e.g. an SCP or permission boundary the engine
	// does not evaluate. This is the refuted verdict the flywheel needs.
	p := ssrfPath()
	escalation := assertionsFor(p)[1]
	o := NewFixtureOracle(map[string]Result{
		escalation.Key(): {Decision: Denied, Evidence: "SCP denies iam:* in this OU"},
	}, Allowed)

	rec, err := Attempt(context.Background(), o, p, "t1", clock)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != validation.Refuted {
		t.Fatalf("outcome = %s, want refuted", rec.Outcome)
	}
	if rec.PredictedScore == 0 {
		t.Error("a refuted verdict still needs the predicted score it refutes")
	}
	if !contains(rec.Evidence, "SCP denies") {
		t.Errorf("evidence should cite the denial, got %q", rec.Evidence)
	}
}

func TestInertAWSOracleNeverConfirms(t *testing.T) {
	// The live oracle is inert in the skeleton: it must yield only Partial, so an
	// accidental run cannot pollute calibration with fabricated confirmations.
	rec, err := Attempt(context.Background(), NewAWSOracle(), ssrfPath(), "t1", clock)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != validation.Partial {
		t.Errorf("inert oracle outcome = %s, want partial", rec.Outcome)
	}
}

// TestClosesTheFlywheelLoop is the whole point of the skeleton: oracle verdicts,
// fed to the real calibration store, produce a real calibration signal. The engine
// predicted ~0.81 for every path, but reality (the oracle) refuted 4 of 10 - so the
// observed rate must land near 0.6 and the verdict must read overconfident. Nowhere
// does the test assert the outcome per path; the oracle decides, exactly as AWS would.
func TestClosesTheFlywheelLoop(t *testing.T) {
	store, err := validation.New("") // in-memory
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		p := ssrfPath()
		p.ID = fmt.Sprintf("ap-%02d", i) // distinct ids so verdicts don't overwrite

		// Reality refutes the escalation on 4 of the 10 (a boundary/SCP they share).
		decisions := map[string]Result{}
		if i < 4 {
			decisions[assertionsFor(p)[1].Key()] = Result{Decision: Denied, Evidence: "permission boundary caps iam:*"}
		}
		o := NewFixtureOracle(decisions, Allowed)

		rec, err := Attempt(context.Background(), o, p, "t1", clock)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Put(rec); err != nil {
			t.Fatal(err)
		}
	}

	cal := store.Calibration("t1")
	if cal.Samples != 10 {
		t.Fatalf("expected 10 scored verdicts, got %d", cal.Samples)
	}
	if cal.ObservedRate < 0.55 || cal.ObservedRate > 0.65 {
		t.Errorf("observed rate = %.2f, want ~0.60 (6 of 10 confirmed)", cal.ObservedRate)
	}
	if cal.MeanPredicted <= cal.ObservedRate {
		t.Errorf("engine predicted %.2f but reality delivered %.2f - this should read as overconfidence",
			cal.MeanPredicted, cal.ObservedRate)
	}
	// The engine over-promised, so the flywheel should recommend scaling scores down.
	if cal.RecommendedScale == 0 || cal.RecommendedScale >= 1 {
		t.Errorf("recommended scale = %.2f, want <1 (scores should be pulled down)", cal.RecommendedScale)
	}
	t.Logf("loop closed: predicted %.2f, observed %.2f, verdict %q, scale %.2f",
		cal.MeanPredicted, cal.ObservedRate, cal.Verdict, cal.RecommendedScale)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestLoadFixtureOracle(t *testing.T) {
	o, err := LoadFixtureOracle("testdata/lab-run.json")
	if err != nil {
		t.Fatal(err)
	}
	denied, _ := o.Check(context.Background(), Assertion{Kind: KindIAM, Principal: "role", Action: "iam:*", Resource: "admin"})
	if denied.Decision != Denied || !contains(denied.Evidence, "SCP") {
		t.Errorf("expected denied-with-evidence from fixture, got %+v", denied)
	}
	// Terse string form decodes too, and the fallback applies to unlisted keys.
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
