package validation

import (
	"errors"
	"math"
	"strings"
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

// The two calibration tracks must grade the right prediction against the right
// event and never cross-contaminate: path-scoped verdicts grade S(P), target-scoped
// verdicts grade the per-target compromise probability.
func TestCalibrationScopeSplit(t *testing.T) {
	s := newStore(t)
	// 3 path-scoped verdicts, each with S(P)=0.9.
	for i, o := range []Outcome{Confirmed, Confirmed, Refuted} {
		if _, err := s.Put(Record{Tenant: "acme", PathID: pathID("p", i), Outcome: o,
			Source: "test", Scope: ScopePath, PredictedScore: 0.9}); err != nil {
			t.Fatal(err)
		}
	}
	// 2 target-scoped verdicts: S(P)=0.9 but compromise=0.4. The target track must
	// grade 0.4, NOT the 0.9 path score.
	for i, o := range []Outcome{Confirmed, Refuted} {
		if _, err := s.Put(Record{Tenant: "acme", PathID: pathID("t", i), Outcome: o,
			Source: "test", Scope: ScopeTarget, PredictedScore: 0.9, PredictedCompromise: 0.4}); err != nil {
			t.Fatal(err)
		}
	}
	cal := s.Calibration("acme")

	if cal.Samples != 3 {
		t.Errorf("path track samples = %d, want 3 (only path-scoped)", cal.Samples)
	}
	if math.Abs(cal.MeanPredicted-0.9) > 1e-9 {
		t.Errorf("path track meanPredicted = %v, want 0.9 (S(P))", cal.MeanPredicted)
	}
	if cal.Target == nil {
		t.Fatal("target-scoped verdicts present but cal.Target is nil")
	}
	if cal.Target.Samples != 2 {
		t.Errorf("target track samples = %d, want 2 (only target-scoped)", cal.Target.Samples)
	}
	if math.Abs(cal.Target.MeanPredicted-0.4) > 1e-9 {
		t.Errorf("target track meanPredicted = %v, want 0.4 (compromise, not the 0.9 S(P))", cal.Target.MeanPredicted)
	}
	if cal.Target.Target != nil {
		t.Error("the nested target track must not itself carry a target")
	}
}

// A target-scoped verdict with no captured compromise (offline / target not live)
// is excluded from the target track and must never leak into the path track.
func TestCalibrationTargetScopeExcludedWithoutCompromise(t *testing.T) {
	s := newStore(t)
	if _, err := s.Put(Record{Tenant: "acme", PathID: "t1", Outcome: Confirmed,
		Source: "test", Scope: ScopeTarget, PredictedScore: 0.9}); err != nil {
		t.Fatal(err)
	}
	cal := s.Calibration("acme")
	if cal.HasData {
		t.Error("path track HasData = true; a target-scoped verdict must not feed the path track")
	}
	if cal.Target != nil {
		t.Error("target track present, but the verdict carried no compromise prediction to grade")
	}
}

// The P1 payoff: when the miscalibration is structured by evidence basis - here the
// SAME score 0.6 runs hot for epss (observed ~0.2) and cold for heuristic (~0.8) - a
// global monotone map sees only the score and pools both to ~0.5, but a per-basis
// Platt correction fixes each provenance class separately and beats it materially.
func TestPerBasisRecalibrationBeatsGlobal(t *testing.T) {
	s := newStore(t)
	put := func(i int, basis string, y Outcome) {
		id := basis + string(rune('a'+i))
		if _, err := s.Put(Record{Tenant: "acme", PathID: id, Outcome: y,
			Source: "test", PredictedScore: 0.6, WeightBasis: basis}); err != nil {
			t.Fatal(err)
		}
	}
	// epss: 12 refuted + 3 confirmed → observed 0.2 (score 0.6 runs hot).
	for i := 0; i < 12; i++ {
		put(i, "epss", Refuted)
	}
	for i := 12; i < 15; i++ {
		put(i, "epss", Confirmed)
	}
	// heuristic: 3 refuted + 12 confirmed → observed 0.8 (score 0.6 runs cold).
	for i := 0; i < 3; i++ {
		put(i, "heuristic", Refuted)
	}
	for i := 3; i < 15; i++ {
		put(i, "heuristic", Confirmed)
	}

	cal := s.Calibration("acme")
	if cal.Samples != 30 {
		t.Fatalf("samples = %d, want 30", cal.Samples)
	}
	if cal.BrierRecalibratedByBasis <= 0 {
		t.Fatal("per-basis recalibration was not computed")
	}
	if cal.BrierRecalibratedByBasis >= cal.BrierRecalibrated-basisImprovementThreshold {
		t.Errorf("per-basis Brier %.3f should beat the global %.3f by > %.2f (bias is provenance-structured)",
			cal.BrierRecalibratedByBasis, cal.BrierRecalibrated, basisImprovementThreshold)
	}
	if !strings.Contains(cal.Diagnosis, "per-basis") {
		t.Errorf("diagnosis = %q, want the per-basis recalibration recommendation", cal.Diagnosis)
	}
	if len(cal.BasisSegments) != 2 {
		t.Errorf("basis segments = %d, want 2 (epss, heuristic)", len(cal.BasisSegments))
	}
	// The published per-basis curves must move off the identity (a≈0,b≈1) in opposite
	// directions: epss pulled down, heuristic pulled up.
	var epss, heur *BasisRecalibration
	for i := range cal.RecalibrationByBasis {
		switch cal.RecalibrationByBasis[i].Basis {
		case "epss":
			epss = &cal.RecalibrationByBasis[i]
		case "heuristic":
			heur = &cal.RecalibrationByBasis[i]
		}
	}
	if epss == nil || heur == nil {
		t.Fatal("missing per-basis recalibration for epss/heuristic")
	}
	epssCal := sigmoidP(epss.Intercept + epss.Slope*logitP(0.6))
	heurCal := sigmoidP(heur.Intercept + heur.Slope*logitP(0.6))
	if !(epssCal < 0.5 && heurCal > 0.5) {
		t.Errorf("per-basis correction at 0.6: epss→%.2f (want <0.5), heuristic→%.2f (want >0.5)", epssCal, heurCal)
	}
}

func TestPutRejectsInvalidScope(t *testing.T) {
	s := newStore(t)
	_, err := s.Put(Record{Tenant: "acme", PathID: "p1", Outcome: Confirmed, Source: "test", Scope: "bogus"})
	if !errors.Is(err, ErrInvalidScope) {
		t.Errorf("Put with bogus scope: err = %v, want ErrInvalidScope", err)
	}
}
