package validation

import "context"

import "testing"

// putEdge files an edge-scoped verdict - the shape internal/kevholdout produces.
func putEdge(t *testing.T, s *Store, cve string, outcome Outcome, predicted float64) {
	t.Helper()
	if _, err := s.Put(context.Background(), Record{
		Tenant:         "acme",
		Outcome:        outcome,
		Scope:          ScopeEdge,
		Source:         "kev-holdout",
		Route:          cve,
		PredictedScore: predicted,
	}); err != nil {
		t.Fatalf("putEdge(%s,%s,%v): %v", cve, outcome, predicted, err)
	}
}

// Edge verdicts grade a per-CVE hop probability, which is neither S(P) nor per-target
// compromise. Letting them into the headline track would move the number an operator
// reads about their attack paths using data about the CVE feed.
func TestEdgeVerdictsDoNotEnterThePathTrack(t *testing.T) {
	s := newStore(t)
	put(t, s, "p1", Confirmed, 0.8)
	put(t, s, "p2", Refuted, 0.2)
	for i, cve := range []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"} {
		outcome := Refuted
		if i == 0 {
			outcome = Confirmed
		}
		putEdge(t, s, cve, outcome, 0.5)
	}

	cal, _ := s.Calibration(context.Background(), "acme")
	if cal.Samples != 2 {
		t.Fatalf("path track has %d samples, want the 2 path verdicts only", cal.Samples)
	}
	if cal.Edge == nil {
		t.Fatal("edge track missing: the edge verdicts were dropped instead of routed")
	}
	if cal.Edge.Samples != 5 {
		t.Errorf("edge track has %d samples, want 5", cal.Edge.Samples)
	}
	if cal.Target != nil {
		t.Errorf("edge verdicts leaked into the target track")
	}
}

// The graded event (CISA catalogues the CVE inside the window) is narrower than the
// modelled one (an attacker traverses this hop), so the level offset is dominated by
// that mismatch. Publishing a scale would invite someone to apply it to the engine.
func TestEdgeTrackPublishesNoRescale(t *testing.T) {
	s := newStore(t)
	// Enough samples that the path track would happily emit a scale and a diagnosis.
	for i := 0; i < 40; i++ {
		outcome := Refuted
		if i%10 == 0 {
			outcome = Confirmed
		}
		putEdge(t, s, string(rune('A'+i))+"-cve", outcome, 0.6)
	}

	cal, _ := s.Calibration(context.Background(), "acme")
	if cal.Edge == nil || !cal.Edge.HasData {
		t.Fatal("edge track absent or empty")
	}
	if cal.Edge.RecommendedScale != 0 {
		t.Errorf("edge track published RecommendedScale = %v, want none", cal.Edge.RecommendedScale)
	}
	if cal.Edge.RecalibrationMap != nil || cal.Edge.RecalibrationByBasis != nil {
		t.Errorf("edge track published a recalibration map")
	}
	if cal.Edge.Diagnosis != "" {
		t.Errorf("edge track published a diagnosis %q, which reads as engine advice", cal.Edge.Diagnosis)
	}
	// What must survive: the discrimination evidence.
	if cal.Edge.Brier <= 0 || len(cal.Edge.Bins) == 0 {
		t.Errorf("edge track dropped the evidence it exists to provide (brier=%v, bins=%d)",
			cal.Edge.Brier, len(cal.Edge.Bins))
	}
}

// The same CVE is forecast again each window it survives, and each closed forecast is
// an independent sample. If edge verdicts replaced by key the way path verdicts do, a
// year of monthly windows would collapse to one row per CVE.
func TestEdgeVerdictsAccumulateRatherThanReplace(t *testing.T) {
	s := newStore(t)
	putEdge(t, s, "CVE-2024-0001", Refuted, 0.30) // window 1: did not enter KEV
	putEdge(t, s, "CVE-2024-0001", Refuted, 0.35) // window 2: still did not
	putEdge(t, s, "CVE-2024-0001", Confirmed, 0.40)

	cal, _ := s.Calibration(context.Background(), "acme")
	if cal.Edge == nil {
		t.Fatal("edge track missing")
	}
	if cal.Edge.Samples != 3 {
		t.Fatalf("edge track kept %d of 3 verdicts for the same CVE - windows are being collapsed", cal.Edge.Samples)
	}
}

func TestEdgeScopeIsValid(t *testing.T) {
	if !ValidScope(ScopeEdge) {
		t.Fatal("ScopeEdge rejected by ValidScope, so the API would refuse holdout verdicts")
	}
}
