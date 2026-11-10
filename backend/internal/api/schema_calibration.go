package api

import (
	"time"

	"github.com/graphql-go/graphql"
	"github.com/luiacuaniello/perspectivegraph/internal/coverage"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/labrecord"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// How far the scores can be trusted: the red-team and BAS verdicts, the calibration measured from them, and the lab runs that test the engine against AWS.

func (a *API) calibrationTypes(t *schemaTypes) {
	validationMetricsType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "ValidationMetrics",
		Description: "Evidence-based trust over the *validated* subset of paths (NOT a global claim): precision = confirmed/(confirmed+refuted), recall = confirmed/(confirmed+missed).",
		Fields: graphql.Fields{
			"confirmed": &graphql.Field{Type: graphql.Int, Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Confirmed })},
			"refuted":   &graphql.Field{Type: graphql.Int, Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Refuted })},
			"partial":   &graphql.Field{Type: graphql.Int, Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Partial })},
			"missed":    &graphql.Field{Type: graphql.Int, Description: "Real paths a tester found that the engine did NOT surface (false negatives).", Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Missed })},
			"tested":    &graphql.Field{Type: graphql.Int, Description: "Paths the engine surfaced and that were tested (confirmed+refuted+partial).", Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Tested })},
			"precision": &graphql.Field{Type: graphql.Float, Description: "confirmed/(confirmed+refuted); null until any path is confirmed or refuted.", Resolve: field[validation.Metrics](func(m validation.Metrics) any {
				if m.Confirmed+m.Refuted == 0 {
					return nil
				}
				return m.Precision
			})},
			"recall": &graphql.Field{Type: graphql.Float, Description: "confirmed/(confirmed+missed); null until a confirmed or missed verdict exists.", Resolve: field[validation.Metrics](func(m validation.Metrics) any {
				if m.Confirmed+m.Missed == 0 {
					return nil
				}
				return m.Recall
			})},
		},
	})

	reliabilityBinType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "ReliabilityBin",
		Description: "One bucket of the reliability diagram: of tested paths whose predicted score fell in [low,high), meanPredicted is their average forecast and observedRate the fraction actually confirmed. Well-calibrated ⇒ the two are equal (points on the diagonal).",
		Fields: graphql.Fields{
			"low":           &graphql.Field{Type: graphql.Float, Resolve: field[validation.ReliabilityBin](func(b validation.ReliabilityBin) any { return b.Low })},
			"high":          &graphql.Field{Type: graphql.Float, Resolve: field[validation.ReliabilityBin](func(b validation.ReliabilityBin) any { return b.High })},
			"count":         &graphql.Field{Type: graphql.Int, Resolve: field[validation.ReliabilityBin](func(b validation.ReliabilityBin) any { return b.Count })},
			"meanPredicted": &graphql.Field{Type: graphql.Float, Resolve: field[validation.ReliabilityBin](func(b validation.ReliabilityBin) any { return b.MeanPredicted })},
			"observedRate":  &graphql.Field{Type: graphql.Float, Resolve: field[validation.ReliabilityBin](func(b validation.ReliabilityBin) any { return b.ObservedRate })},
		},
	})

	calibrationSegmentType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "CalibrationSegment",
		Description: "Calibration over a subset of verdicts (e.g. correlated-hop vs independent, long vs short paths), so a residual error can be attributed: concentrated on correlated/long paths ⇒ structural (the independence assumption), pointing at a correlation-aware model (#6).",
		Fields: graphql.Fields{
			"name":          &graphql.Field{Type: graphql.String, Resolve: field[validation.CalibrationSegment](func(s validation.CalibrationSegment) any { return s.Name })},
			"samples":       &graphql.Field{Type: graphql.Int, Resolve: field[validation.CalibrationSegment](func(s validation.CalibrationSegment) any { return s.Samples })},
			"brier":         &graphql.Field{Type: graphql.Float, Resolve: field[validation.CalibrationSegment](func(s validation.CalibrationSegment) any { return s.Brier })},
			"ece":           &graphql.Field{Type: graphql.Float, Resolve: field[validation.CalibrationSegment](func(s validation.CalibrationSegment) any { return s.ECE })},
			"meanPredicted": &graphql.Field{Type: graphql.Float, Resolve: field[validation.CalibrationSegment](func(s validation.CalibrationSegment) any { return s.MeanPredicted })},
			"observedRate":  &graphql.Field{Type: graphql.Float, Resolve: field[validation.CalibrationSegment](func(s validation.CalibrationSegment) any { return s.ObservedRate })},
			"verdict":       &graphql.Field{Type: graphql.String, Resolve: field[validation.CalibrationSegment](func(s validation.CalibrationSegment) any { return s.Verdict })},
		},
	})

	calibrationPointType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "CalibrationPoint",
		Description: "One step of the learned recalibration curve: a raw model score mapped to the calibrated probability observed for it. A consumer can apply the curve to recalibrate scores out-of-band (the engine never silently rewrites them).",
		Fields: graphql.Fields{
			"score":      &graphql.Field{Type: graphql.Float, Resolve: field[validation.CalibrationPoint](func(p validation.CalibrationPoint) any { return p.Score })},
			"calibrated": &graphql.Field{Type: graphql.Float, Resolve: field[validation.CalibrationPoint](func(p validation.CalibrationPoint) any { return p.Calibrated })},
		},
	})

	basisRecalibrationType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "BasisRecalibration",
		Description: "The learned per-basis Platt correction (P1): for a path whose weakest evidence hop is `basis`, apply sigmoid(intercept + slope*logit(score)). Slope~1 and intercept~0 mean that basis is already calibrated; a large shift means that provenance class (e.g. EPSS, heuristic) is systematically over/under-confident.",
		Fields: graphql.Fields{
			"basis":     &graphql.Field{Type: graphql.String, Resolve: field[validation.BasisRecalibration](func(b validation.BasisRecalibration) any { return b.Basis })},
			"samples":   &graphql.Field{Type: graphql.Int, Resolve: field[validation.BasisRecalibration](func(b validation.BasisRecalibration) any { return b.Samples })},
			"intercept": &graphql.Field{Type: graphql.Float, Resolve: field[validation.BasisRecalibration](func(b validation.BasisRecalibration) any { return b.Intercept })},
			"slope":     &graphql.Field{Type: graphql.Float, Resolve: field[validation.BasisRecalibration](func(b validation.BasisRecalibration) any { return b.Slope })},
		},
	})

	detectionStatsType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "DetectionStats",
		Description: "Of reachable (confirmed) paths carrying a detection report, how often the path was actually caught/blocked - the evidence for the detection axis (#7). A high rate on high-score paths means the score over-predicts *undetected* compromise.",
		Fields: graphql.Fields{
			"tested":                 &graphql.Field{Type: graphql.Int, Resolve: field[validation.DetectionStats](func(d validation.DetectionStats) any { return d.Tested })},
			"detected":               &graphql.Field{Type: graphql.Int, Resolve: field[validation.DetectionStats](func(d validation.DetectionStats) any { return d.Detected })},
			"detectionRate":          &graphql.Field{Type: graphql.Float, Resolve: field[validation.DetectionStats](func(d validation.DetectionStats) any { return d.DetectionRate })},
			"highScoreTested":        &graphql.Field{Type: graphql.Int, Resolve: field[validation.DetectionStats](func(d validation.DetectionStats) any { return d.HighScoreTested })},
			"highScoreDetectionRate": &graphql.Field{Type: graphql.Float, Resolve: field[validation.DetectionStats](func(d validation.DetectionStats) any { return d.HighScoreDetectionRate })},
		},
	})

	discriminationType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "Discrimination",
		Description: "Does the score ORDER dangerous paths above harmless ones? AUC: the probability a confirmed path outranks a refuted one, ties counted half. 0.5 is a coin, 1 is perfect separation, below 0.5 the order is inverted. A separate question from calibration - a well-calibrated score can separate nothing, and a sharply separating one can be badly miscalibrated. Partial verdicts are excluded: half credit is not a class.",
		Fields: graphql.Fields{
			"positives": &graphql.Field{Type: graphql.Int, Description: "Confirmed verdicts carrying the score.", Resolve: field[validation.Discrimination](func(d validation.Discrimination) any { return d.Positives })},
			"negatives": &graphql.Field{Type: graphql.Int, Description: "Refuted verdicts carrying the score.", Resolve: field[validation.Discrimination](func(d validation.Discrimination) any { return d.Negatives })},
			"auc": &graphql.Field{Type: graphql.Float, Description: "P(a confirmed path outranks a refuted one). Null until there is at least one of each.", Resolve: field[validation.Discrimination](func(d validation.Discrimination) any {
				if !d.HasData {
					return nil
				}
				return d.AUC
			})},
			"aucLow": &graphql.Field{Type: graphql.Float, Description: "Lower bound of an approximate 95% interval (Hanley-McNeil, widened on small samples so perfect separation does not report zero width).", Resolve: field[validation.Discrimination](func(d validation.Discrimination) any {
				if !d.HasData {
					return nil
				}
				return d.AUCLow
			})},
			"aucHigh": &graphql.Field{Type: graphql.Float, Description: "Upper bound of the same interval. An interval containing 0.5 means the order cannot yet be told apart from a coin.", Resolve: field[validation.Discrimination](func(d validation.Discrimination) any {
				if !d.HasData {
					return nil
				}
				return d.AUCHigh
			})},
			"verdict": &graphql.Field{Type: graphql.String, Description: "discriminates | indistinguishable-from-chance | inverted | insufficient-data (fewer than ten of either class: the AUC is still shown, not judged).", Resolve: field[validation.Discrimination](func(d validation.Discrimination) any { return d.Verdict })},
			"hasData": &graphql.Field{Type: graphql.Boolean, Resolve: field[validation.Discrimination](func(d validation.Discrimination) any { return d.HasData })},
		},
	})

	calibrationType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "Calibration",
		Description: "Does the number mean anything? Pairs each tested path's predicted score with its observed outcome (confirmed→1, refuted→0, partial→0.5) and grades the forecast: Brier/log-loss/ECE plus a reliability diagram. The production artifact that lets you stand behind \"55%\" as a probability, not a vibe.",
		Fields: graphql.Fields{
			"samples":       &graphql.Field{Type: graphql.Int, Description: "Tested verdicts carrying a predicted score (the calibration sample size).", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.Samples })},
			"brier":         &graphql.Field{Type: graphql.Float, Description: "Mean (predicted-observed)², in [0,1]; lower is better (0 = perfect).", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.Brier })},
			"logLoss":       &graphql.Field{Type: graphql.Float, Description: "Mean cross-entropy; punishes confident misses harder than Brier.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.LogLoss })},
			"ece":           &graphql.Field{Type: graphql.Float, Description: "Expected calibration error: the sample-weighted gap between predicted and observed across bins, in [0,1]; lower is better.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.ECE })},
			"meanPredicted": &graphql.Field{Type: graphql.Float, Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.MeanPredicted })},
			"observedRate":  &graphql.Field{Type: graphql.Float, Description: "The realized base rate: fraction of tested paths that confirmed.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.ObservedRate })},
			"recommendedScale": &graphql.Field{Type: graphql.Float, Description: "Advisory: observed/predicted. <1 ⇒ scores run hot (overconfident); >1 ⇒ cold. Null until there are enough samples to trust it.", Resolve: field[validation.Calibration](func(c validation.Calibration) any {
				if c.RecommendedScale == 0 {
					return nil
				}
				return c.RecommendedScale
			})},
			"verdict":                  &graphql.Field{Type: graphql.String, Description: "well-calibrated (mean and per-bin agree: a score can be read as a probability) | calibrated-on-average (the mean agrees but the bins do not, ECE above tolerance - no claim about what any particular score means) | overconfident | underconfident | insufficient-data.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.Verdict })},
			"hasData":                  &graphql.Field{Type: graphql.Boolean, Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.HasData })},
			"bins":                     &graphql.Field{Type: graphql.NewList(reliabilityBinType), Description: "The reliability diagram, fixed buckets over [0,1] (empty buckets have count 0).", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.Bins })},
			"brierRecalibrated":        &graphql.Field{Type: graphql.Float, Description: "Brier after an isotonic recalibration - the floor a monotone rescale can reach. If it's good, recalibration suffices (apply recalibrationMap); if it's still high, the model lacks resolution and no rescale fixes it (the line past which #6/#7 are warranted).", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.BrierRecalibrated })},
			"recalibrationMap":         &graphql.Field{Type: graphql.NewList(calibrationPointType), Description: "The learned monotone curve (raw score → calibrated probability) a consumer can apply out-of-band. The engine never silently rewrites scores.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.RecalibrationMap })},
			"segments":                 &graphql.Field{Type: graphql.NewList(calibrationSegmentType), Description: "Calibration split by path structure (correlated/independent hops, long/short), so a residual error can be attributed to a structural cause (#6).", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.Segments })},
			"basisSegments":            &graphql.Field{Type: graphql.NewList(calibrationSegmentType), Description: "Calibration split by the path's weakest evidence basis (kev/epss/cvss/severity/heuristic), so a residual error can be attributed to a provenance class - the diagnostic behind per-basis recalibration (P1).", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.BasisSegments })},
			"brierRecalibratedByBasis": &graphql.Field{Type: graphql.Float, Description: "Brier after a *per-basis* Platt recalibration (cross-validated). When it beats brierRecalibrated (the global monotone floor) by a material margin, the miscalibration is structured by evidence provenance and a single global rescale is not enough - apply recalibrationByBasis.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.BrierRecalibratedByBasis })},
			"recalibrationByBasis":     &graphql.Field{Type: graphql.NewList(basisRecalibrationType), Description: "The learned per-basis correction (P1), applied out-of-band per the path's weakest basis.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.RecalibrationByBasis })},
			"detection": &graphql.Field{Type: detectionStatsType, Description: "Detection-axis summary (#7): how often reachable paths were caught. Null until a confirmed verdict carries a detection report.", Resolve: field[validation.Calibration](func(c validation.Calibration) any {
				if c.Detection == nil {
					return nil
				}
				return *c.Detection
			})},
			"discrimination": &graphql.Field{Type: graphql.NewNonNull(discriminationType), Description: "Whether this track's own predicted score orders confirmed verdicts above refuted ones (AUC).", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.Discrimination })},
			"priorityDiscrimination": &graphql.Field{Type: discriminationType, Description: "Whether the triage ORDER - Priority, the axis an operator sorts by - puts confirmed paths above refuted ones. Path-scoped track only; null until a verdict carries a Priority captured at verdict time. It grades the order against an exploitability outcome while Priority also weighs target sensitivity and blast radius by design, so read a modest value as \"the order is not only about reachability\", not as a defect on its own.", Resolve: field[validation.Calibration](func(c validation.Calibration) any {
				if c.PriorityDiscrimination == nil {
					return nil
				}
				return *c.PriorityDiscrimination
			})},
			"diagnosis":  &graphql.Field{Type: graphql.String, Description: "The one-line gate recommendation derived from all of the above: calibrated / recalibrate-first / structural (#6) / detection-axis (#7) / per-basis recalibration (P1) / low-resolution / inverted-order. The answer to \"and therefore what should we build?\". Any claim it makes about the ranking is read from discrimination, and quotes its AUC.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.Diagnosis })},
			"persistent": &graphql.Field{Type: graphql.Boolean, Description: "Whether the verdict store survives a restart (VALIDATIONS_PATH set). False ⇒ the calibration dataset is in-memory and lost on restart - fine for a demo, but set it for a real calibration program.", Resolve: field[validation.Calibration](func(c validation.Calibration) any { return c.Persistent })},
		},
	})
	// The target-scoped track, added after creation so the field can reference the
	// type recursively. The top-level fields grade a specific path's S(P) against
	// "this path was traversable"; this nested track grades the per-target compromise
	// probability against "the crown jewel was reached at all (by any route)" - the
	// correct, un-conflated event for a target-reached verdict. Null when there are no
	// target-scoped verdicts; its own target is always null.
	calibrationType.AddFieldConfig("target", &graphql.Field{
		Type:        calibrationType,
		Description: "Target-scoped calibration: predicted per-target compromise probability vs \"the crown jewel was reached at all\", kept separate from the per-path S(P) track so the two different events are not conflated.",
		Resolve: field[validation.Calibration](func(c validation.Calibration) any {
			if c.Target == nil {
				return nil
			}
			return *c.Target
		}),
	})

	// The edge-scoped track: sealed per-CVE forecasts graded a window later against
	// whether that CVE entered CISA's KEV catalogue (internal/kevholdout). A third
	// quantity again - the per-hop input the other two are built from - so it gets its
	// own track for the same reason target does. It deliberately carries no
	// recommendedScale or diagnosis: the graded event is narrower than the modelled one,
	// so its level offset must not be read as advice to move the engine.
	calibrationType.AddFieldConfig("edge", &graphql.Field{
		Type:        calibrationType,
		Description: "Edge-scoped calibration: a per-CVE hop probability, sealed before the outcome existed and graded against whether that CVE later became known-exploited. Builds itself from public feeds with no red team. Null until the first forecast window closes; carries no recommendedScale, because the graded event (the CVE is catalogued) is narrower than the modelled one (an attacker traverses this hop).",
		Resolve: field[validation.Calibration](func(c validation.Calibration) any {
			if c.Edge == nil {
				return nil
			}
			return *c.Edge
		}),
	})

	// What the engine has actually been fed. Every other number here qualifies what it
	// SHOWS; this qualifies what it could not see. A path-finding engine on incomplete
	// input produces false negatives, and those are invisible - nobody chases a route
	// they were never shown - so "no path found" has to be readable as "none in what I
	// was given", with the given part stated.
	ingestSourceType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "IngestSource",
		Description: "One collector's contribution to this tenant's graph: when it was last heard from and how much it delivered. A stale source means the engine is answering from data that has stopped arriving.",
		Fields: graphql.Fields{
			"source":    &graphql.Field{Type: graphql.String, Description: "Collector name (trivy, falco, iam, …).", Resolve: field[coverage.Source](func(c coverage.Source) any { return c.Source })},
			"firstSeen": &graphql.Field{Type: graphql.String, Description: "When this source was first heard from (RFC3339).", Resolve: field[coverage.Source](func(c coverage.Source) any { return c.First.UTC().Format(time.RFC3339) })},
			"lastSeen":  &graphql.Field{Type: graphql.String, Description: "When it last delivered (RFC3339).", Resolve: field[coverage.Source](func(c coverage.Source) any { return c.Last.UTC().Format(time.RFC3339) })},
			"events":    &graphql.Field{Type: graphql.Int, Description: "Accepted ingest calls.", Resolve: field[coverage.Source](func(c coverage.Source) any { return c.Events })},
			"nodes":     &graphql.Field{Type: graphql.Int, Description: "Assets contributed.", Resolve: field[coverage.Source](func(c coverage.Source) any { return c.Nodes })},
			"edges":     &graphql.Field{Type: graphql.Int, Description: "Relationships contributed.", Resolve: field[coverage.Source](func(c coverage.Source) any { return c.Edges })},
			"stale":     &graphql.Field{Type: graphql.Boolean, Description: "Silent for longer than the staleness window: this source is describing an older estate than the rest.", Resolve: field[coverage.Source](func(c coverage.Source) any { return c.Stale })},
			"silentFor": &graphql.Field{Type: graphql.String, Description: "How long it has been silent, when stale.", Resolve: field[coverage.Source](func(c coverage.Source) any { return c.Silent })},
		},
	})

	calibrationTrendPointType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "CalibrationTrendPoint",
		Description: "One sample of the calibration trend - the headline calibration numbers at a point in time, so the evidence accumulating over a calibration program is visible.",
		Fields: graphql.Fields{
			"at":      &graphql.Field{Type: graphql.String, Resolve: field[history.CalibrationSample](func(c history.CalibrationSample) any { return c.At.UTC().Format(time.RFC3339) })},
			"brier":   &graphql.Field{Type: graphql.Float, Resolve: field[history.CalibrationSample](func(c history.CalibrationSample) any { return c.Brier })},
			"ece":     &graphql.Field{Type: graphql.Float, Resolve: field[history.CalibrationSample](func(c history.CalibrationSample) any { return c.ECE })},
			"samples": &graphql.Field{Type: graphql.Int, Resolve: field[history.CalibrationSample](func(c history.CalibrationSample) any { return c.Samples })},
		},
	})

	labCheckType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "LabCheck",
		Description: "One question a lab put both to AWS and to the engine, on a real account: a fact a route's step rests on, such as whether a bucket is open or a role can escalate.",
		Fields: graphql.Fields{
			"case":     &graphql.Field{Type: graphql.String, Description: "The resource or principal, as the lab names it.", Resolve: field[labrecord.Check](func(c labrecord.Check) any { return c.Case })},
			"question": &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Check](func(c labrecord.Check) any { return c.Question })},
			"referee":  &graphql.Field{Type: graphql.String, Description: "Where AWS's answer came from.", Resolve: field[labrecord.Check](func(c labrecord.Check) any { return c.Referee })},
			"aws":      &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Check](func(c labrecord.Check) any { return c.AWS })},
			"engine":   &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Check](func(c labrecord.Check) any { return c.Engine })},
			"verdict":  &graphql.Field{Type: graphql.String, Description: "agree | disagree | unsettled.", Resolve: field[labrecord.Check](func(c labrecord.Check) any { return c.Verdict })},
			"note":     &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Check](func(c labrecord.Check) any { return c.Note })},
		},
	})
	labRunType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "LabRun",
		Description: "A lab's latest run on a real AWS account, built into this version: how its rules were checked, not a fact about the estate being read.",
		Fields: graphql.Fields{
			"lab":       &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Lab })},
			"title":     &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Title })},
			"command":   &graphql.Field{Type: graphql.String, Description: "How to run it again.", Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Command })},
			"region":    &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Region })},
			"engine":    &graphql.Field{Type: graphql.String, Description: "The engine version the run was made with.", Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Engine })},
			"ranAt":     &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.RanAt.UTC().Format(time.RFC3339) })},
			"cost":      &graphql.Field{Type: graphql.String, Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Cost })},
			"agreed":    &graphql.Field{Type: graphql.Int, Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Count(labrecord.Agree) })},
			"disagreed": &graphql.Field{Type: graphql.Int, Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Count(labrecord.Disagree) })},
			"unsettled": &graphql.Field{Type: graphql.Int, Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Count(labrecord.Unsettled) })},
			"checks":    &graphql.Field{Type: graphql.NewList(labCheckType), Resolve: field[labrecord.Run](func(r labrecord.Run) any { return r.Checks })},
		},
	})

	t.validationMetricsType = validationMetricsType
	t.reliabilityBinType = reliabilityBinType
	t.calibrationSegmentType = calibrationSegmentType
	t.calibrationPointType = calibrationPointType
	t.basisRecalibrationType = basisRecalibrationType
	t.detectionStatsType = detectionStatsType
	t.discriminationType = discriminationType
	t.calibrationType = calibrationType
	t.ingestSourceType = ingestSourceType
	t.calibrationTrendPointType = calibrationTrendPointType
	t.labCheckType = labCheckType
	t.labRunType = labRunType
}

func (a *API) calibrationQueries(t *schemaTypes) graphql.Fields {
	validationMetricsType, calibrationType, calibrationTrendPointType, labRunType := t.validationMetricsType, t.calibrationType, t.calibrationTrendPointType, t.labRunType
	return graphql.Fields{
		"validation": &graphql.Field{
			Type:        validationMetricsType,
			Description: "Red-team/BAS validation metrics - precision/recall over the tested subset. The evidence that the engine is grounded against reality, not just modeled.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				return a.view(p.Context).validationMetrics()
			},
		},
		"calibration": &graphql.Field{
			Type:        calibrationType,
			Description: "Probability calibration over tested verdicts: does a path scored 0.8 actually confirm ~80% of the time? Brier/log-loss/ECE + a reliability diagram - the demo→production gate for trusting the scores as probabilities.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				return a.view(p.Context).calibration()
			},
		},
		"labRuns": &graphql.Field{
			Type:        graphql.NewList(labRunType),
			Description: "The latest run of each lab that checks this version's rules on a real AWS account, with AWS as the referee - newest first. Built into the binary: evidence about the engine, not about the estate it reads.",
			Resolve: func(graphql.ResolveParams) (any, error) {
				return labrecord.All()
			},
		},
		"calibrationTrend": &graphql.Field{
			Type:        graphql.NewList(calibrationTrendPointType),
			Description: "Calibration headline (Brier/ECE/samples) over time, sampled each analysis pass - so a calibration program can watch the evidence accumulate and the scores improve.",
			Args: graphql.FieldConfigArgument{
				"points": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 200, Description: "How many recent samples to return (most recent last)."},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				limit, _ := p.Args["points"].(int)
				return a.view(p.Context).calibrationTrend(limit), nil
			},
		},
	}
}
