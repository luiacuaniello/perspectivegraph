package validation

// Calibration diagnostics - the instrument that turns "are we calibrated?" into
// "and therefore what should we build?". Three lenses on the same verdict dataset:
//
//   - Recalibration (isotonic): the Brier a monotone rescale can reach. If it is
//     good, you just apply the published map - no new model needed. If the residual
//     stays high, recalibration can't save you (the score lacks *resolution*).
//   - Segments: split calibration by path structure (correlated vs independent hops,
//     long vs short). Residual error that concentrates on correlated/long paths is
//     *structural* - the independence assumption - and points at a correlation-aware
//     model (#6).
//   - Detection: of reachable (confirmed) paths, how many were actually caught. A
//     high rate means the score over-predicts *undetected* compromise and the model
//     needs a detection axis (#7).
//
// diagnose() folds all three into one gate recommendation.

import (
	"math"
	"math/rand/v2"
	"sort"
)

const (
	// longPathHops is the hop count at/above which a path counts as "long" for the
	// length segment - where the product's independence error compounds most.
	longPathHops = 5
	// highScoreThreshold is the predicted score at/above which a confirmed path is a
	// "high-score reachable" path for the detection axis.
	highScoreThreshold = 0.6
	// detectionConcern: a high-score detection rate at/above this means defenses are
	// catching the very paths the score ranks as dangerous (#7 signal).
	detectionConcern = 0.4
	// lowResolutionSkill: resolution / uncertainty (the fraction of the base-rate
	// variance the score actually explains, like an R²). Below this the score barely
	// discriminates real from fake, and no rescale can help - a constant forecast is
	// perfectly calibrated yet useless. Resolution is measured from bins (not isotonic)
	// so it doesn't overfit in-sample.
	lowResolutionSkill = 0.1
)

// calSample is one scored verdict reduced to what the diagnostics need: predicted
// probability, observed outcome, and the path features used for segmentation.
type calSample struct {
	p, y       float64
	correlated bool
	hops       int
}

// CalibrationPoint is one step of the learned recalibration curve (raw model score
// → calibrated probability), so a consumer can recalibrate scores out-of-band.
type CalibrationPoint struct {
	Score      float64 `json:"score"`
	Calibrated float64 `json:"calibrated"`
}

// CalibrationSegment is the calibration over a subset of verdicts (e.g. correlated-hop
// paths), so a residual error can be attributed to a structural cause.
type CalibrationSegment struct {
	Name          string  `json:"name"`
	Samples       int     `json:"samples"`
	Brier         float64 `json:"brier"`
	ECE           float64 `json:"ece"`
	MeanPredicted float64 `json:"mean_predicted"`
	ObservedRate  float64 `json:"observed_rate"`
	Verdict       string  `json:"verdict"`
}

// DetectionStats summarizes how often reachable (confirmed) paths were caught or
// blocked - the evidence for the detection axis (#7).
type DetectionStats struct {
	Tested                 int     `json:"tested"`    // confirmed verdicts carrying a detection report
	Detected               int     `json:"detected"`  // of those, how many were caught/blocked
	DetectionRate          float64 `json:"detection_rate"`
	HighScoreTested        int     `json:"high_score_tested"`
	HighScoreDetectionRate float64 `json:"high_score_detection_rate"`
	HasData                bool    `json:"has_data"`
}

// coreStats is the basic calibration of a set of samples, reused for the global
// report and every segment.
type coreStats struct {
	n        int
	brier    float64
	logLoss  float64
	meanPred float64
	obsRate  float64
	ece      float64
	verdict  string
}

// calibrationStats computes Brier, log loss, ECE, the means, and the verdict over a
// set of samples - the shared core behind the global report and the segments.
func calibrationStats(samples []calSample) coreStats {
	n := len(samples)
	if n == 0 {
		return coreStats{verdict: "insufficient-data"}
	}
	var sumBrier, sumLogLoss, sumPred, sumObs float64
	binPredSum := make([]float64, reliabilityBins)
	binObsSum := make([]float64, reliabilityBins)
	binCount := make([]int, reliabilityBins)
	for _, s := range samples {
		sumPred += s.p
		sumObs += s.y
		sumBrier += (s.p - s.y) * (s.p - s.y)
		sumLogLoss += crossEntropy(s.p, s.y)
		b := binOf(s.p)
		binPredSum[b] += s.p
		binObsSum[b] += s.y
		binCount[b]++
	}
	nn := float64(n)
	c := coreStats{n: n, brier: sumBrier / nn, logLoss: sumLogLoss / nn, meanPred: sumPred / nn, obsRate: sumObs / nn}
	for i := 0; i < reliabilityBins; i++ {
		if binCount[i] == 0 {
			continue
		}
		bc := float64(binCount[i])
		c.ece += (bc / nn) * math.Abs(binPredSum[i]/bc-binObsSum[i]/bc)
	}
	c.verdict = verdictFor(n, c.meanPred-c.obsRate)
	return c
}

// verdictFor labels a calibration from its sample count and predicted-minus-observed
// gap, withholding a read below the sample floor.
func verdictFor(n int, gap float64) string {
	if n < minCalibrationSamples {
		return "insufficient-data"
	}
	switch {
	case gap > calibrationGapTolerance:
		return "overconfident"
	case gap < -calibrationGapTolerance:
		return "underconfident"
	default:
		return "well-calibrated"
	}
}

// reliabilityDiagram bins the samples into the fixed reliability buckets for display.
func reliabilityDiagram(samples []calSample) []ReliabilityBin {
	bins := emptyBins()
	predSum := make([]float64, reliabilityBins)
	obsSum := make([]float64, reliabilityBins)
	for _, s := range samples {
		b := binOf(s.p)
		predSum[b] += s.p
		obsSum[b] += s.y
		bins[b].Count++
	}
	for i := range bins {
		if bins[i].Count == 0 {
			continue
		}
		bc := float64(bins[i].Count)
		bins[i].MeanPredicted = predSum[i] / bc
		bins[i].ObservedRate = obsSum[i] / bc
	}
	return bins
}

const (
	// cvMinSamples: below this, k folds are too thin to cross-validate, so the
	// recalibrated Brier is reported in-sample (the optimistic floor) with that caveat.
	cvMinSamples = 20
	cvFolds      = 5
)

// isoBlock is one step of a fitted isotonic map: the block's upper score boundary and
// its fitted (monotone non-decreasing) probability.
type isoBlock struct {
	maxX, fitted float64
}

// fitIsotonic runs pool-adjacent-violators over the samples (sorted by score) and
// returns the monotone step blocks (for prediction) and the publishable map points.
func fitIsotonic(samples []calSample) (blocks []isoBlock, pts []CalibrationPoint) {
	if len(samples) == 0 {
		return nil, nil
	}
	ss := append([]calSample(nil), samples...)
	sort.Slice(ss, func(i, j int) bool { return ss[i].p < ss[j].p })
	type b struct {
		sumY, sumP, maxP float64
		cnt              int
	}
	var bl []b
	for _, s := range ss {
		bl = append(bl, b{sumY: s.y, sumP: s.p, maxP: s.p, cnt: 1})
		for len(bl) >= 2 {
			a, c := bl[len(bl)-2], bl[len(bl)-1]
			if a.sumY/float64(a.cnt) <= c.sumY/float64(c.cnt) {
				break
			}
			bl = bl[:len(bl)-2]
			bl = append(bl, b{sumY: a.sumY + c.sumY, sumP: a.sumP + c.sumP, maxP: c.maxP, cnt: a.cnt + c.cnt})
		}
	}
	for _, x := range bl {
		f := x.sumY / float64(x.cnt)
		blocks = append(blocks, isoBlock{maxX: x.maxP, fitted: f})
		pts = append(pts, CalibrationPoint{Score: x.sumP / float64(x.cnt), Calibrated: f})
	}
	return blocks, pts
}

// predictIsotonic evaluates the step map at p (the first block whose upper boundary
// covers p, clamped to the ends).
func predictIsotonic(blocks []isoBlock, p float64) float64 {
	for _, b := range blocks {
		if p <= b.maxX {
			return b.fitted
		}
	}
	if len(blocks) > 0 {
		return blocks[len(blocks)-1].fitted
	}
	return p
}

// recalibrate returns the Brier a monotone (isotonic) rescale can reach and the map to
// apply (the full-data fit, for publishing). The Brier is k-fold CROSS-VALIDATED when
// there are enough samples - an honest out-of-sample floor rather than the optimistic
// in-sample fit that overfits exactly when data is thin (the real-world case).
func recalibrate(samples []calSample) (float64, []CalibrationPoint) {
	n := len(samples)
	if n == 0 {
		return 0, nil
	}
	blocks, pts := fitIsotonic(samples) // full-data map for publishing/applying
	if n >= cvMinSamples {
		return isotonicBrierCV(samples, cvFolds), pts
	}
	// In-sample fallback (too few to cross-validate).
	var sum float64
	for _, s := range samples {
		d := predictIsotonic(blocks, s.p) - s.y
		sum += d * d
	}
	return sum / float64(n), pts
}

// isotonicBrierCV estimates the recalibrated Brier out-of-sample: a deterministic
// k-fold split (so the report is reproducible), fitting the isotonic map on the train
// folds and scoring the held-out one.
func isotonicBrierCV(samples []calSample, k int) float64 {
	n := len(samples)
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	rng := rand.New(rand.NewPCG(0x5eed, 0x1234))
	rng.Shuffle(n, func(i, j int) { idx[i], idx[j] = idx[j], idx[i] })
	fold := make([]int, n)
	for pos, i := range idx {
		fold[i] = pos % k
	}
	var sum float64
	cnt := 0
	for f := 0; f < k; f++ {
		var train []calSample
		for i := range samples {
			if fold[i] != f {
				train = append(train, samples[i])
			}
		}
		blocks, _ := fitIsotonic(train)
		for i := range samples {
			if fold[i] == f {
				d := predictIsotonic(blocks, samples[i].p) - samples[i].y
				sum += d * d
				cnt++
			}
		}
	}
	if cnt == 0 {
		return 0
	}
	return sum / float64(cnt)
}

// calibrationSegments splits the samples by path structure and calibrates each, so a
// residual error can be attributed. Empty segments are omitted.
func calibrationSegments(samples []calSample) []CalibrationSegment {
	defs := []struct {
		name string
		pred func(calSample) bool
	}{
		{"correlated-hops", func(s calSample) bool { return s.correlated }},
		{"independent-hops", func(s calSample) bool { return !s.correlated }},
		{"long-path", func(s calSample) bool { return s.hops >= longPathHops }},
		{"short-path", func(s calSample) bool { return s.hops > 0 && s.hops < longPathHops }},
	}
	var out []CalibrationSegment
	for _, d := range defs {
		var sub []calSample
		for _, s := range samples {
			if d.pred(s) {
				sub = append(sub, s)
			}
		}
		if len(sub) == 0 {
			continue
		}
		c := calibrationStats(sub)
		out = append(out, CalibrationSegment{
			Name: d.name, Samples: c.n, Brier: c.brier, ECE: c.ece,
			MeanPredicted: c.meanPred, ObservedRate: c.obsRate, Verdict: c.verdict,
		})
	}
	return out
}

// detectionStats summarizes, over confirmed verdicts that carry a detection report,
// how often the (reachable) path was caught - overall and among high-score paths.
func detectionStats(records []Record) *DetectionStats {
	var tested, detected, hiTested, hiDetected int
	for _, r := range records {
		if r.Outcome != Confirmed || r.Detected == nil {
			continue
		}
		tested++
		if *r.Detected {
			detected++
		}
		if r.PredictedScore >= highScoreThreshold {
			hiTested++
			if *r.Detected {
				hiDetected++
			}
		}
	}
	if tested == 0 {
		return nil
	}
	ds := &DetectionStats{Tested: tested, Detected: detected, HighScoreTested: hiTested, HasData: true}
	ds.DetectionRate = float64(detected) / float64(tested)
	if hiTested > 0 {
		ds.HighScoreDetectionRate = float64(hiDetected) / float64(hiTested)
	}
	return ds
}

// segmentByName returns the named segment, or nil.
func segmentByName(segs []CalibrationSegment, name string) *CalibrationSegment {
	for i := range segs {
		if segs[i].Name == name {
			return &segs[i]
		}
	}
	return nil
}

// diagnose folds the calibration, its recalibration floor, the structural segments
// and the detection summary into a single gate recommendation - the one line that
// answers "and therefore what should we build?".
func diagnose(cal Calibration) string {
	// The detection axis can fire regardless of calibration quality: if reachable,
	// high-score paths are frequently caught, the score over-predicts *undetected*
	// compromise no matter how well it predicts reachability.
	if d := cal.Detection; d != nil && d.HighScoreTested >= minCalibrationSamples && d.HighScoreDetectionRate >= detectionConcern {
		return "detection-axis (#7): reachable high-score paths are frequently detected/blocked, so the score over-predicts undetected compromise - add a P(reach and not-detected) term."
	}
	// Resolution first: if the score barely discriminates (per-bin observed rates hug
	// the base rate), no rescale helps - a constant forecast is calibrated yet useless.
	if resolutionSkill(cal) < lowResolutionSkill {
		return "low-resolution: the score barely separates real from fake paths (a rescale can't help) - revisit the per-edge evidence before adding model complexity."
	}
	// Structural (#6): a segment miscalibrated *more than the rest* needs its own curve,
	// which a single global rescale can't provide.
	if s := structuralSegment(cal); s != "" {
		return s
	}
	// Has resolution, no structural concentration ⇒ any remaining calibration error is a
	// monotone rescale away (apply recalibrationMap), unless it's already calibrated.
	if cal.Verdict == "well-calibrated" {
		return "calibrated: predicted scores match observed outcomes; no model change indicated - keep validating."
	}
	return "recalibrate-first: the ranking is sound but the scores are mis-scaled - apply the recalibrationMap before building any new model."
}

// resolutionSkill is the Murphy resolution divided by the uncertainty (base-rate
// variance) - the fraction of the variance the score explains, like an R². Computed
// from the reliability bins so it doesn't overfit the way an in-sample isotonic fit
// would. Returns a large value when uncertainty is ~0 (a degenerate base rate) so the
// low-resolution branch doesn't fire spuriously.
func resolutionSkill(cal Calibration) float64 {
	u := cal.ObservedRate * (1 - cal.ObservedRate)
	if u < 0.02 {
		return 1
	}
	total := 0
	for _, b := range cal.Bins {
		total += b.Count
	}
	if total == 0 {
		return 1
	}
	var resolution float64
	for _, b := range cal.Bins {
		if b.Count == 0 {
			continue
		}
		d := b.ObservedRate - cal.ObservedRate
		resolution += (float64(b.Count) / float64(total)) * d * d
	}
	return resolution / u
}

// structuralSegment returns a #6 diagnosis when a structural segment (correlated or
// long paths) is miscalibrated noticeably more than its complement - a per-segment
// error a single global rescale can't fix.
func structuralSegment(cal Calibration) string {
	globalGap := math.Abs(cal.MeanPredicted - cal.ObservedRate)
	check := func(segName, refName, msg string) string {
		seg := segmentByName(cal.Segments, segName)
		if seg == nil || seg.Samples < minCalibrationSamples || seg.Verdict == "well-calibrated" || seg.Verdict == "insufficient-data" {
			return ""
		}
		ref := globalGap
		if r := segmentByName(cal.Segments, refName); r != nil && r.Samples >= minCalibrationSamples {
			ref = math.Abs(r.MeanPredicted - r.ObservedRate)
		}
		if math.Abs(seg.MeanPredicted-seg.ObservedRate) > ref+calibrationGapTolerance {
			return msg
		}
		return ""
	}
	if m := check("correlated-hops", "independent-hops",
		"structural (#6): error concentrates on correlated-hop paths, where the independence assumption breaks - consider a correlation-aware model (Bayesian Attack Graph)."); m != "" {
		return m
	}
	return check("long-path", "short-path",
		"structural (#6): error concentrates on long paths, where the product compounds its error - consider a correlation-aware model.")
}
