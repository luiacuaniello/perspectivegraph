package validation

import (
	"math"
	"testing"
)

func TestRecalibrateIsMonotoneAndLowersBrier(t *testing.T) {
	// A non-monotone observed pattern: raw Brier 0.2, isotonic should beat it.
	samples := []calSample{{p: 0.2, y: 0}, {p: 0.4, y: 1}, {p: 0.6, y: 0}, {p: 0.8, y: 1}}
	raw := calibrationStats(samples).brier
	brierRecal, m := recalibrate(samples)
	if brierRecal >= raw {
		t.Errorf("recalibrated Brier %.4f should be < raw %.4f", brierRecal, raw)
	}
	// The map must be non-decreasing in the calibrated value.
	for i := 1; i < len(m); i++ {
		if m[i].Calibrated < m[i-1].Calibrated-1e-12 {
			t.Errorf("recalibration map not monotone at %d: %.3f < %.3f", i, m[i].Calibrated, m[i-1].Calibrated)
		}
	}
}

func TestRecalibrateCVNotFooledByNoise(t *testing.T) {
	// Outcomes are a hash bit of the index, uncorrelated with the predicted score:
	// there is no learnable signal, so an HONEST recalibrated Brier must stay near the
	// uncertainty (~0.25), not be talked down to ~0 by in-sample isotonic overfitting.
	var samples []calSample
	for i := 0; i < 200; i++ {
		h := uint64(i)
		h ^= h >> 33
		h *= 0xff51afd7ed558ccd
		h ^= h >> 33
		samples = append(samples, calSample{p: 0.05 + 0.9*float64(i)/199, y: float64(h & 1)})
	}
	brier, _ := recalibrate(samples)
	if brier < 0.2 {
		t.Errorf("CV recalibrated Brier = %.3f on pure noise; should stay near the uncertainty (~0.25), not overfit to ~0", brier)
	}
	// Deterministic: the report must not jitter between identical inputs.
	brier2, _ := recalibrate(samples)
	if brier != brier2 {
		t.Errorf("recalibrate not deterministic: %.6f vs %.6f", brier, brier2)
	}
}

func TestCalibrationSegmentsAttributeCorrelatedError(t *testing.T) {
	var samples []calSample
	// Correlated-hop paths the model under-predicts (low score, all confirm).
	for i := 0; i < 8; i++ {
		samples = append(samples, calSample{p: 0.4, y: 1, correlated: true, hops: 3})
	}
	// Independent paths that are well-calibrated (predicted 0.5, half confirm).
	for i := 0; i < 8; i++ {
		y := 0.0
		if i%2 == 0 {
			y = 1
		}
		samples = append(samples, calSample{p: 0.5, y: y, correlated: false, hops: 2})
	}
	segs := calibrationSegments(samples)
	corr := segmentByName(segs, "correlated-hops")
	if corr == nil {
		t.Fatal("expected a correlated-hops segment")
	}
	if corr.Verdict != "underconfident" {
		t.Errorf("correlated segment verdict = %q, want underconfident (obs %.2f >> pred %.2f)", corr.Verdict, corr.ObservedRate, corr.MeanPredicted)
	}
}

func TestDetectionStats(t *testing.T) {
	yes, no := true, false
	recs := []Record{
		{Outcome: Confirmed, PredictedScore: 0.9, Detected: &yes},
		{Outcome: Confirmed, PredictedScore: 0.8, Detected: &no},
		{Outcome: Confirmed, PredictedScore: 0.3, Detected: &yes}, // low score
		{Outcome: Confirmed, PredictedScore: 0.7},                 // no detection report - excluded
		{Outcome: Refuted, PredictedScore: 0.9, Detected: &yes},   // not confirmed - excluded
	}
	ds := detectionStats(recs)
	if ds == nil || ds.Tested != 3 {
		t.Fatalf("tested = %v, want 3 confirmed verdicts with a detection report", ds)
	}
	if ds.Detected != 2 {
		t.Errorf("detected = %d, want 2", ds.Detected)
	}
	if ds.HighScoreTested != 2 { // 0.9 and 0.8 are >= 0.6
		t.Errorf("highScoreTested = %d, want 2", ds.HighScoreTested)
	}
	if math.Abs(ds.HighScoreDetectionRate-0.5) > 1e-9 { // 0.9 detected, 0.8 not
		t.Errorf("highScoreDetectionRate = %.3f, want 0.5", ds.HighScoreDetectionRate)
	}
}

func TestDiagnoseGate(t *testing.T) {
	// Bins with the observed rate spread away from the base rate ⇒ the score has
	// resolution (used by the non-low-resolution cases to clear that branch).
	resolvedBins := []ReliabilityBin{{Count: 50, ObservedRate: 0.1}, {Count: 50, ObservedRate: 0.9}}
	// Bins whose observed rates hug the base rate ⇒ no resolution.
	flatBins := []ReliabilityBin{{Count: 50, ObservedRate: 0.5}, {Count: 50, ObservedRate: 0.5}}

	cases := []struct {
		name string
		cal  Calibration
		want string
	}{
		{
			"detection fires regardless",
			Calibration{Verdict: "well-calibrated", ObservedRate: 0.5, Bins: resolvedBins, Detection: &DetectionStats{HighScoreTested: 10, HighScoreDetectionRate: 0.6}},
			"#7",
		},
		{
			"well calibrated",
			Calibration{Verdict: "well-calibrated", ObservedRate: 0.5, Bins: resolvedBins},
			"calibrated:",
		},
		{
			"recalibrate first",
			Calibration{Verdict: "overconfident", MeanPredicted: 0.6, ObservedRate: 0.4, Bins: resolvedBins},
			"recalibrate-first",
		},
		{
			"structural correlated",
			Calibration{
				Verdict: "underconfident", MeanPredicted: 0.5, ObservedRate: 0.6, Bins: resolvedBins,
				Segments: []CalibrationSegment{
					{Name: "correlated-hops", Samples: 12, Verdict: "underconfident", MeanPredicted: 0.5, ObservedRate: 0.9},
					{Name: "independent-hops", Samples: 12, Verdict: "well-calibrated", MeanPredicted: 0.5, ObservedRate: 0.5},
				},
			},
			"#6",
		},
		{
			"low resolution",
			Calibration{Verdict: "well-calibrated", ObservedRate: 0.5, Bins: flatBins},
			"low-resolution",
		},
	}
	for _, tc := range cases {
		got := diagnose(tc.cal)
		if !contains(got, tc.want) {
			t.Errorf("%s: diagnosis %q does not contain %q", tc.name, got, tc.want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestCalibrationEndToEndWithSegmentsAndDetection(t *testing.T) {
	s := newStore(t)
	yes := true
	// 10 correlated paths the model under-predicts (0.4 → all confirm), one carrying a
	// detection report, so segments + detection both populate through the public API.
	for i := 0; i < 10; i++ {
		det := (*bool)(nil)
		if i == 0 {
			det = &yes
		}
		if _, err := s.Put(Record{Tenant: "acme", PathID: pathID("c", i), Outcome: Confirmed, Source: "bas", PredictedScore: 0.4, CorrelatedHops: true, Hops: 6, Detected: det}); err != nil {
			t.Fatal(err)
		}
	}
	cal := s.Calibration("acme")
	if cal.Samples != 10 {
		t.Fatalf("samples = %d, want 10", cal.Samples)
	}
	if segmentByName(cal.Segments, "correlated-hops") == nil {
		t.Error("expected a correlated-hops segment in the end-to-end report")
	}
	if cal.Detection == nil || cal.Detection.Tested != 1 {
		t.Errorf("expected detection stats with 1 tested, got %v", cal.Detection)
	}
	if cal.Diagnosis == "" {
		t.Error("expected a non-empty diagnosis")
	}
}
