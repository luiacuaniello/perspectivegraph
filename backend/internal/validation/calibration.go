package validation

// Calibration closes the loop between what the engine *predicts* and what
// reality *confirms* - the single thing that separates a demo from a production
// risk tool. precision/recall (see Metrics) tell you whether a surfaced path was
// real; calibration tells you whether the *number* attached to it means anything:
// of the paths the engine scored at ~0.8, do ~80% actually turn out exploitable?
//
// We pair each tested verdict's predicted score S(P) with its observed outcome
// (confirmed → 1, refuted → 0, partial → 0.5) and report the standard scoring
// rules a forecaster is judged by:
//
//   - Brier score  = mean (p - y)²            (sharpness+calibration; lower better)
//   - Log loss     = -mean[y ln p + (1-y)ln(1-p)]  (penalizes confident misses)
//   - ECE          = Σ (nₖ/N) · |meanPredₖ - obsRateₖ|  (binned calibration gap)
//   - a reliability diagram (predicted vs observed per bin)
//
// and an honest verdict: well-calibrated / overconfident / underconfident, plus a
// RecommendedScale (the multiplicative nudge that would best align predictions to
// observations). The scale is *advisory* - we surface it rather than silently
// rescaling scores, because on a thin sample that would be fitting noise. This is
// the artifact that lets an operator stand behind "55%" as a probability, not a
// vibe.

import "math"

// reliabilityBins is the number of equal-width buckets in the reliability diagram
// over [0,1]. Five keeps each bucket populated on the modest verdict counts a real
// program accumulates, while still showing the shape of the calibration curve.
const reliabilityBins = 5

// minCalibrationSamples is the floor below which the calibration verdict is just
// sampling noise: we still report the raw numbers, but label the verdict
// "insufficient-data" and withhold a RecommendedScale rather than overfit.
const minCalibrationSamples = 8

// calibrationGapTolerance is how far mean-predicted may sit from observed-rate
// before we call the model over/under-confident rather than well-calibrated.
const calibrationGapTolerance = 0.1

// ReliabilityBin is one bucket of the reliability diagram: of the tested paths
// whose predicted score fell in [Low, High), MeanPredicted is their average
// prediction and ObservedRate the fraction that were actually confirmed. A
// well-calibrated model has MeanPredicted ≈ ObservedRate in every populated bin
// (points hug the diagonal).
type ReliabilityBin struct {
	Low           float64 `json:"low"`
	High          float64 `json:"high"`
	Count         int     `json:"count"`
	MeanPredicted float64 `json:"mean_predicted"`
	ObservedRate  float64 `json:"observed_rate"`
}

// Calibration is the rolled-up calibration report for a tenant: how well the
// engine's predicted path scores match observed red-team/BAS outcomes.
type Calibration struct {
	Samples       int              `json:"samples"`        // tested verdicts carrying a predicted score
	Brier         float64          `json:"brier"`          // mean (p-y)², in [0,1], lower is better
	LogLoss       float64          `json:"log_loss"`       // mean cross-entropy, ≥0, lower is better
	ECE           float64          `json:"ece"`            // expected calibration error, in [0,1], lower is better
	MeanPredicted float64          `json:"mean_predicted"` // average predicted probability
	ObservedRate  float64          `json:"observed_rate"`  // average observed outcome (the realized base rate)
	Bins          []ReliabilityBin `json:"bins"`           // reliability diagram (fixed buckets; empty ones have Count 0)
	// RecommendedScale is observed/predicted: multiply scores by it to best match
	// reality. ~1 ⇒ calibrated; <1 ⇒ scores run hot (overconfident); >1 ⇒ scores run
	// cold. Advisory only, and 0 (omitted) until there are enough samples to trust it.
	RecommendedScale float64 `json:"recommended_scale,omitempty"`
	// BrierRecalibrated is the Brier score *after* an isotonic recalibration of the
	// predictions - the floor recalibration alone can reach (it removes all reliability
	// error, leaving only resolution). The gap Brier - BrierRecalibrated is the part a
	// simple rescale fixes; a BrierRecalibrated that is still high means the model lacks
	// *resolution* (can't separate real from fake), which no rescale repairs - that's
	// the line past which you need a better model (#6) or a missing axis (#7).
	BrierRecalibrated float64 `json:"brier_recalibrated"`
	// RecalibrationMap is the learned monotone curve (raw score → calibrated
	// probability) a consumer can apply to recalibrate scores out-of-band, without the
	// engine silently rewriting them. Empty until there is enough data.
	RecalibrationMap []CalibrationPoint `json:"recalibration_map,omitempty"`
	// Segments break the calibration down by path structure (correlated vs independent
	// hops, long vs short), so a residual error can be *attributed*: concentrated on
	// correlated/long paths ⇒ structural (#6).
	Segments []CalibrationSegment `json:"segments,omitempty"`
	// BasisSegments break the calibration down by the path's weakest evidence basis
	// (kev/epss/cvss/severity/heuristic), so a residual error can be attributed to a
	// provenance class - the diagnostic behind per-basis recalibration (P1).
	BasisSegments []CalibrationSegment `json:"basis_segments,omitempty"`
	// BrierRecalibratedByBasis is the Brier a *per-basis* Platt recalibration reaches
	// (cross-validated). When it beats BrierRecalibrated (the global monotone floor) by
	// a material margin, the miscalibration is provenance-structured and a single global
	// rescale is not enough - apply RecalibrationByBasis instead.
	BrierRecalibratedByBasis float64 `json:"brier_recalibrated_by_basis,omitempty"`
	// RecalibrationByBasis is the learned per-basis correction (apply
	// sigmoid(intercept + slope·logit(score)) for a path whose weakest hop basis is
	// Basis), published for out-of-band use like RecalibrationMap.
	RecalibrationByBasis []BasisRecalibration `json:"recalibration_by_basis,omitempty"`
	// Detection summarizes, over confirmed (reachable) verdicts that carry a detection
	// report, how often the path was actually caught/blocked - the evidence for the
	// detection axis (#7). Nil until any confirmed verdict carries a Detected flag.
	Detection *DetectionStats `json:"detection,omitempty"`
	// Diagnosis is the one-line gate recommendation derived from all of the above:
	// calibrated / recalibrate-first / structural-#6 / detection-#7 / low-resolution.
	Diagnosis string `json:"diagnosis,omitempty"`
	// Target is the *target-scoped* calibration: verdicts that validated whether a
	// crown jewel was reached AT ALL (by any route) grade the per-target compromise
	// probability, not a single path's S(P). It is kept a separate track because they
	// are different events - grading S(P) against an any-route outcome would bias the
	// report. The top-level fields are the path-scoped track (S(P) vs a specific path).
	// Nil when there are no target-scoped verdicts; its own Target is always nil.
	Target *Calibration `json:"target,omitempty"`
	// Persistent reports whether the verdict store survives a restart (VALIDATIONS_PATH
	// set). When false, the calibration dataset is in-memory and is lost on restart -
	// fine for a demo, but for a real engagement that accumulates verdicts over weeks it
	// must be set, so the report surfaces the gap rather than letting it bite silently.
	Persistent bool `json:"persistent"`
	// Verdict is the qualitative read: "well-calibrated" | "overconfident" |
	// "underconfident" | "insufficient-data".
	Verdict string `json:"verdict"`
	HasData bool   `json:"has_data"` // false ⇒ no scored verdicts yet; the metrics are undefined
}

// observedOutcome maps a verdict to the [0,1] label a scoring rule consumes: a
// confirmed path was exploitable (1), a refuted one was a false positive (0), and
// a partial gets half credit. The bool reports whether the outcome counts as a
// calibration sample at all (missed verdicts don't - they have no scored path).
func observedOutcome(o Outcome) (y float64, isSample bool) {
	switch o {
	case Confirmed:
		return 1, true
	case Refuted:
		return 0, true
	case Partial:
		return 0.5, true
	default: // Missed and anything else
		return 0, false
	}
}

// Calibration computes a tenant's calibration report as two independent tracks,
// each grading the right prediction against the right event: the top-level fields
// are the *path-scoped* track (predicted S(P) vs "this path was traversable"), and
// the nested Target is the *target-scoped* track (predicted per-target compromise
// probability vs "the crown jewel was reached at all"). Conflating them - grading a
// path's S(P) against an any-route outcome - would bias the report, so the scope on
// each verdict routes it to the correct track. A nil *Store and an empty dataset
// both yield a well-formed, zero-valued report (HasData false).
func (s *Store) Calibration(tenant string) Calibration {
	if s == nil {
		return Calibration{Bins: emptyBins(), Verdict: "insufficient-data"}
	}
	persistent := s.Persistent()
	tenant = tenantKey(tenant)

	s.mu.RLock()
	records := s.byTenant[tenant]
	detection := detectionStats(records)
	pathSamples := make([]calSample, 0, len(records))
	targetSamples := make([]calSample, 0, len(records))
	for _, r := range records {
		y, isSample := observedOutcome(r.Outcome)
		if !isSample {
			continue
		}
		if scopeOrDefault(r.Scope) == ScopeTarget {
			if r.PredictedCompromise > 0 {
				targetSamples = append(targetSamples,
					calSample{p: clampTop(r.PredictedCompromise), y: y, correlated: r.CorrelatedHops, hops: r.Hops, basis: r.WeightBasis})
			}
			continue
		}
		if r.PredictedScore > 0 {
			pathSamples = append(pathSamples,
				calSample{p: clampTop(r.PredictedScore), y: y, correlated: r.CorrelatedHops, hops: r.Hops, basis: r.WeightBasis})
		}
	}
	s.mu.RUnlock()

	// Detection spans all confirmed verdicts (scope-agnostic) and must be set before
	// diagnose(), so each track's diagnosis can raise the detection axis (#7).
	cal := computeCalibration(pathSamples, detection, persistent)
	if len(targetSamples) > 0 {
		tcal := computeCalibration(targetSamples, detection, persistent)
		cal.Target = &tcal
	}
	return cal
}

// computeCalibration grades a set of (prediction, outcome) samples - the shared core
// behind both the path-scoped and target-scoped tracks. detection is attached before
// diagnose() so the detection axis (#7) can fire; the caller attaches Target.
func computeCalibration(samples []calSample, detection *DetectionStats, persistent bool) Calibration {
	cal := Calibration{Bins: emptyBins(), Verdict: "insufficient-data", Persistent: persistent, Detection: detection}
	n := len(samples)
	if n == 0 {
		return cal
	}
	core := calibrationStats(samples)
	cal.Samples = core.n
	cal.HasData = true
	cal.Brier = core.brier
	cal.LogLoss = core.logLoss
	cal.MeanPredicted = core.meanPred
	cal.ObservedRate = core.obsRate
	cal.ECE = core.ece
	cal.Verdict = core.verdict
	cal.Bins = reliabilityDiagram(samples)

	// Below the sample floor we report the raw numbers but withhold the calibrated
	// reads (rescale, recalibration, segment diagnosis) - they would just fit noise.
	if n < minCalibrationSamples {
		cal.Verdict = "insufficient-data"
		return cal
	}
	if cal.MeanPredicted > 0 {
		cal.RecommendedScale = clamp(cal.ObservedRate/cal.MeanPredicted, 0.1, 10)
	}
	// Recalibration: isotonic fit removes all reliability error, so its Brier is the
	// floor a rescale can reach. Publish the map (raw → calibrated) for out-of-band
	// use rather than silently rewriting the engine's scores.
	cal.BrierRecalibrated, cal.RecalibrationMap = recalibrate(samples)
	cal.Segments = calibrationSegments(samples)
	// P1: does the miscalibration differ by evidence basis? Fit a per-basis correction
	// and measure how much it beats the global monotone rescale.
	cal.BasisSegments = basisSegments(samples)
	cal.BrierRecalibratedByBasis, cal.RecalibrationByBasis = recalibrateByBasis(samples)
	cal.Diagnosis = diagnose(cal)
	return cal
}

// clampTop caps a probability at 1 (a server-captured prediction should already be
// in range, but a client-supplied fallback might not be).
func clampTop(p float64) float64 {
	if p > 1 {
		return 1
	}
	return p
}

// crossEntropy is the per-sample log loss -[y ln p + (1-y) ln(1-p)], with p
// clamped away from {0,1} so a single confident miss can't send it to +Inf.
func crossEntropy(p, y float64) float64 {
	const eps = 1e-6
	p = clamp(p, eps, 1-eps)
	return -(y*math.Log(p) + (1-y)*math.Log(1-p))
}

// binOf maps a probability to its reliability bucket index, with the top edge
// (p == 1) folded into the last bin.
func binOf(p float64) int {
	b := int(p * reliabilityBins)
	if b >= reliabilityBins {
		b = reliabilityBins - 1
	}
	if b < 0 {
		b = 0
	}
	return b
}

// emptyBins returns the fixed reliability buckets with their [Low,High) ranges set
// and zero counts, so the diagram has a stable shape even before any data lands.
func emptyBins() []ReliabilityBin {
	bins := make([]ReliabilityBin, reliabilityBins)
	w := 1.0 / float64(reliabilityBins)
	for i := range bins {
		bins[i].Low = float64(i) * w
		bins[i].High = float64(i+1) * w
	}
	return bins
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
