package validation

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
				if _, err := s.Put(Record{
					Tenant: "acme", PathID: v.PathID, Outcome: v.Outcome, Source: "selftest",
					PredictedScore: v.PredictedScore, Hops: v.Hops, CorrelatedHops: v.CorrelatedHops, Detected: v.Detected,
				}); err != nil {
					t.Fatalf("put: %v", err)
				}
			}
			cal := s.Calibration("acme")
			if !contains(cal.Diagnosis, sc.WantInDiag) {
				t.Errorf("scenario %q: diagnosis %q does not contain %q (verdict=%s, brierRecal=%.3f, samples=%d)",
					sc.Name, cal.Diagnosis, sc.WantInDiag, cal.Verdict, cal.BrierRecalibrated, cal.Samples)
			}
		})
	}
}
