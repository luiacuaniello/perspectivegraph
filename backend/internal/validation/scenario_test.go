package validation

import "context"

import "testing"

// TestCalibrationScenarioDiagnosesEndToEnd is the CI guard for the diagnostics: for
// every self-test scenario it draws verdicts from that known reality, Puts them, runs
// the full Calibration(), and asserts the gate names the expected cause. It exercises
// the exact pipeline the `genverdicts` CLI does (generation → Put → Calibration →
// diagnose), in-process and deterministically, so a regression in the gate logic fails
// the build rather than surfacing months later on real data.
func TestCalibrationScenarioDiagnosesEndToEnd(t *testing.T) {
	for _, sc := range Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			s := newStore(t)
			verdicts, ok := GenerateScenario(sc.Name, 500, 7)
			if !ok {
				t.Fatalf("unknown scenario %q", sc.Name)
			}
			for _, v := range verdicts {
				if _, err := s.Put(context.Background(), Record{
					Tenant: "acme", PathID: v.PathID, Outcome: v.Outcome, Source: "selftest",
					PredictedScore: v.PredictedScore, Hops: v.Hops, CorrelatedHops: v.CorrelatedHops,
					WeightBasis: v.WeightBasis, Detected: v.Detected,
				}); err != nil {
					t.Fatalf("put: %v", err)
				}
			}
			cal, _ := s.Calibration(context.Background(), "acme")
			if !contains(cal.Diagnosis, sc.WantInDiag) {
				t.Errorf("scenario %q: diagnosis %q does not contain %q (verdict=%s, brierRecal=%.3f, samples=%d)",
					sc.Name, cal.Diagnosis, sc.WantInDiag, cal.Verdict, cal.BrierRecalibrated, cal.Samples)
			}
		})
	}
}

// Calibration and discrimination are separate claims, and the scenarios prove it on 500
// verdicts rather than asserting it in a comment. "overconfident" is badly miscalibrated
// and yet orders paths better than any other scenario; "low-resolution" draws outcomes
// independently of the score, so its order cannot be told apart from a coin. A metric
// that called both of those the same would be measuring calibration twice.
func TestDiscriminationSeparatesSignalFromNoiseEndToEnd(t *testing.T) {
	for _, sc := range Scenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			verdicts, _ := GenerateScenario(sc.Name, 500, 7)
			s, err := New("")
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range verdicts {
				if _, err := s.Put(context.Background(), Record{
					Tenant: "acme", PathID: v.PathID, Outcome: v.Outcome, Source: "genverdicts",
					PredictedScore: v.PredictedScore, Hops: v.Hops, CorrelatedHops: v.CorrelatedHops,
					WeightBasis: v.WeightBasis, Detected: v.Detected, PredictedPriority: v.PredictedPriority,
				}); err != nil {
					t.Fatal(err)
				}
			}
			cal, _ := s.Calibration(context.Background(), "acme")
			d := cal.Discrimination
			want := "discriminates"
			if sc.Name == "low-resolution" {
				want = "indistinguishable-from-chance"
			}
			if d.Verdict != want {
				t.Fatalf("score discrimination %q (AUC %.3f [%.3f, %.3f]), want %q", d.Verdict, d.AUC, d.AUCLow, d.AUCHigh, want)
			}
			if cal.PriorityDiscrimination == nil {
				t.Fatal("synthetic verdicts carry a Priority, yet the triage order was not graded")
			}
			if sc.Name == "overconfident" && !contains(cal.Diagnosis, "recalibrate-first") {
				t.Fatalf("overconfident should still be diagnosed as miscalibrated while it discriminates; diagnosis %q", cal.Diagnosis)
			}
		})
	}
}

// A score whose outcomes do not depend on it can still predict the base rate on average -
// that is all "low-resolution" does: predictions spread over [0.05, 0.95], every outcome a
// coin flip, mean predicted and mean observed both about 0.5. The verdict used to compare
// only those two means and called it well-calibrated, and the Trust page turned that into
// "when it says 70%, roughly 70% is what happens" - false for every bin of this dataset.
func TestAnUninformativeScoreIsNotCalledWellCalibrated(t *testing.T) {
	verdicts, _ := GenerateScenario("low-resolution", 500, 7)
	s, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range verdicts {
		if _, err := s.Put(context.Background(), Record{
			Tenant: "acme", PathID: v.PathID, Outcome: v.Outcome, Source: "genverdicts",
			PredictedScore: v.PredictedScore, Hops: v.Hops, CorrelatedHops: v.CorrelatedHops,
		}); err != nil {
			t.Fatal(err)
		}
	}
	cal, _ := s.Calibration(context.Background(), "acme")
	if cal.Verdict == "well-calibrated" {
		t.Fatalf("an uninformative score was labelled well-calibrated (mean gap %+.3f, ECE %.3f) - the verdict only compared averages",
			cal.MeanPredicted-cal.ObservedRate, cal.ECE)
	}
	if !contains(cal.Diagnosis, "low-resolution") {
		t.Fatalf("diagnosis %q: the fix must not disturb the low-resolution reading", cal.Diagnosis)
	}
}
