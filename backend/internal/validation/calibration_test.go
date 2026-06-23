package validation

import (
	"math"
	"testing"
)

// put is a test helper that records a scored verdict for tenant "acme".
func put(t *testing.T, s *Store, pathID string, outcome Outcome, score float64) {
	t.Helper()
	if _, err := s.Put(Record{Tenant: "acme", PathID: pathID, Outcome: outcome, Source: "test", PredictedScore: score}); err != nil {
		t.Fatalf("put(%s,%s,%v): %v", pathID, outcome, score, err)
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestCalibrationEmpty(t *testing.T) {
	cal := newStore(t).Calibration("acme")
	if cal.HasData {
		t.Errorf("empty store: HasData = true, want false")
	}
	if cal.Verdict != "insufficient-data" {
		t.Errorf("empty store: Verdict = %q, want insufficient-data", cal.Verdict)
	}
	if len(cal.Bins) != reliabilityBins {
		t.Errorf("empty store: %d bins, want %d", len(cal.Bins), reliabilityBins)
	}
	// A nil *Store must not panic and must report a well-formed empty report.
	if (*Store)(nil).Calibration("x").HasData {
		t.Errorf("nil store: HasData = true, want false")
	}
}

func TestCalibrationBrierExact(t *testing.T) {
	s := newStore(t)
	put(t, s, "p1", Confirmed, 0.8) // (0.8-1)^2 = 0.04
	put(t, s, "p2", Refuted, 0.2)   // (0.2-0)^2 = 0.04

	cal := s.Calibration("acme")
	if cal.Samples != 2 {
		t.Fatalf("Samples = %d, want 2", cal.Samples)
	}
	if math.Abs(cal.Brier-0.04) > 1e-9 {
		t.Errorf("Brier = %v, want 0.04", cal.Brier)
	}
	if math.Abs(cal.MeanPredicted-0.5) > 1e-9 {
		t.Errorf("MeanPredicted = %v, want 0.5", cal.MeanPredicted)
	}
	if math.Abs(cal.ObservedRate-0.5) > 1e-9 {
		t.Errorf("ObservedRate = %v, want 0.5", cal.ObservedRate)
	}
	// Below the sample floor we still expose the numbers but withhold a verdict
	// and the advisory rescale.
	if cal.Verdict != "insufficient-data" {
		t.Errorf("Verdict = %q, want insufficient-data (n<%d)", cal.Verdict, minCalibrationSamples)
	}
	if cal.RecommendedScale != 0 {
		t.Errorf("RecommendedScale = %v, want 0 below sample floor", cal.RecommendedScale)
	}
}

func TestCalibrationWellCalibrated(t *testing.T) {
	s := newStore(t)
	// Predicted 0.5 across 10 paths; exactly half confirm. Reality matches the
	// forecast, so the model is well-calibrated and the rescale is ~1.
	for i := 0; i < 5; i++ {
		put(t, s, pathID("c", i), Confirmed, 0.5)
		put(t, s, pathID("r", i), Refuted, 0.5)
	}
	cal := s.Calibration("acme")
	if cal.Samples != 10 {
		t.Fatalf("Samples = %d, want 10", cal.Samples)
	}
	if cal.Verdict != "well-calibrated" {
		t.Errorf("Verdict = %q, want well-calibrated", cal.Verdict)
	}
	if math.Abs(cal.RecommendedScale-1.0) > 1e-9 {
		t.Errorf("RecommendedScale = %v, want 1.0", cal.RecommendedScale)
	}
	// All ten land in the middle bucket [0.4,0.6); its observed rate is 0.5.
	mid := cal.Bins[2]
	if mid.Count != 10 || math.Abs(mid.ObservedRate-0.5) > 1e-9 {
		t.Errorf("middle bin = %+v, want count 10, observed 0.5", mid)
	}
}

func TestCalibrationOverconfident(t *testing.T) {
	s := newStore(t)
	// Scores run hot: predicted 0.9 but only 2/8 actually confirm.
	for i := 0; i < 2; i++ {
		put(t, s, pathID("c", i), Confirmed, 0.9)
	}
	for i := 0; i < 6; i++ {
		put(t, s, pathID("r", i), Refuted, 0.9)
	}
	cal := s.Calibration("acme")
	if cal.Verdict != "overconfident" {
		t.Errorf("Verdict = %q, want overconfident", cal.Verdict)
	}
	if cal.RecommendedScale >= 1 {
		t.Errorf("RecommendedScale = %v, want <1 for hot scores", cal.RecommendedScale)
	}
	// observed 0.25 / predicted 0.9 ≈ 0.278.
	if want := 0.25 / 0.9; math.Abs(cal.RecommendedScale-want) > 1e-9 {
		t.Errorf("RecommendedScale = %v, want %v", cal.RecommendedScale, want)
	}
}

func TestCalibrationExcludesUnscoredAndMissed(t *testing.T) {
	s := newStore(t)
	put(t, s, "scored", Confirmed, 0.7)
	// Unscored verdict (predicted score unknown / pre-calibration) is excluded.
	if _, err := s.Put(Record{Tenant: "acme", PathID: "unscored", Outcome: Confirmed, Source: "test"}); err != nil {
		t.Fatal(err)
	}
	// A "missed" verdict is a false negative with no surfaced path - not a sample.
	if _, err := s.Put(Record{Tenant: "acme", Outcome: Missed, Source: "test", Route: "x->y", PredictedScore: 0.9}); err != nil {
		t.Fatal(err)
	}
	cal := s.Calibration("acme")
	if cal.Samples != 1 {
		t.Errorf("Samples = %d, want 1 (only the scored, non-missed verdict)", cal.Samples)
	}
}

func pathID(prefix string, i int) string {
	return prefix + string(rune('0'+i))
}
