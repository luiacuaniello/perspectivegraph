package validation

// Calibration self-test scenarios - the single source of truth shared by the
// `genverdicts` CLI (which posts them over HTTP) and the in-process CI test (which
// Puts them and asserts the diagnosis). Each scenario draws verdicts from a KNOWN
// reality so the calibration diagnostics can be checked against ground truth without
// real vulnerable infrastructure. This validates the *instrument*, never the engine's
// scores against the real world.

import (
	"fmt"
	"math"
	"math/rand/v2"
)

// SyntheticVerdict is one generated verdict: the model's prediction plus the outcome
// drawn from the scenario's reality, ready to POST or Put.
type SyntheticVerdict struct {
	PathID         string
	Outcome        Outcome
	PredictedScore float64
	Hops           int
	CorrelatedHops bool
	WeightBasis    string
	Detected       *bool
}

// Scenarios is the ordered set of self-test scenarios and the diagnosis each must
// produce (the expectation the CI test asserts).
var Scenarios = []struct {
	Name        string
	WantInDiag  string // substring the diagnosis must contain
	Description string
}{
	{"calibrated", "calibrated:", "reality = the model's own scores"},
	{"overconfident", "recalibrate-first", "reality markedly harder than predicted (p^2.2)"},
	{"underconfident", "recalibrate-first", "reality markedly easier than predicted (p^0.45)"},
	{"correlated", "#6", "correlated-hop paths over-confirm; independents stay calibrated"},
	{"low-resolution", "low-resolution", "outcome independent of the score"},
	{"detection", "#7", "calibrated, but reachable high-score paths are caught"},
	{"per-basis", "per-basis", "EPSS hops run hot, heuristic hops run cold - a global rescale can't fix both"},
}

// groundTruths maps a scenario to its reality model: given the model's predicted path
// score p (and whether the path is correlated-hops), it returns the TRUE per-path
// success probability the outcome is drawn from. The gap between p and this is the
// miscalibration the instrument must detect and attribute.
var groundTruths = map[string]func(p float64, correlated bool, basis string) float64{
	"calibrated":     func(p float64, _ bool, _ string) float64 { return p },
	"overconfident":  func(p float64, _ bool, _ string) float64 { return math.Pow(p, 2.2) },
	"underconfident": func(p float64, _ bool, _ string) float64 { return math.Pow(p, 0.45) },
	"correlated": func(p float64, correlated bool, _ string) float64 {
		if correlated {
			return math.Pow(p, 0.3) // over-confirm only on correlated paths ⇒ structural
		}
		return p
	},
	"low-resolution": func(float64, bool, string) float64 { return 0.5 }, // no resolution
	"detection":      func(p float64, _ bool, _ string) float64 { return p }, // signal is in Detected
	// per-basis: the SAME score means different things by evidence provenance - EPSS
	// hops over-predict (run hot), heuristic hops under-predict (run cold). A single
	// global monotone rescale can't separate them; a per-basis Platt correction can.
	"per-basis": func(p float64, _ bool, basis string) float64 {
		switch basis {
		case "epss":
			return math.Pow(p, 2.2) // hot
		case "heuristic":
			return math.Pow(p, 0.45) // cold
		default:
			return p
		}
	},
}

// GenerateScenario draws `count` synthetic verdicts for a scenario, deterministically
// from `seed`. Returns (nil, false) for an unknown scenario.
func GenerateScenario(scenario string, count int, seed uint64) ([]SyntheticVerdict, bool) {
	gt, ok := groundTruths[scenario]
	if !ok {
		return nil, false
	}
	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	out := make([]SyntheticVerdict, 0, count)
	for i := 0; i < count; i++ {
		p := 0.05 + rng.Float64()*0.9 // predicted score in [0.05, 0.95]
		hops := 1 + rng.IntN(8)       // 1..8 hops
		correlated := rng.Float64() < 0.4
		basis := ""
		if scenario == "per-basis" { // half the verdicts EPSS-based, half heuristic
			if rng.Float64() < 0.5 {
				basis = "epss"
			} else {
				basis = "heuristic"
			}
		}
		isConf := rng.Float64() <= gt(p, correlated, basis)
		v := SyntheticVerdict{
			PathID:         fmt.Sprintf("gv-%s-%d", scenario, i),
			Outcome:        Refuted,
			PredictedScore: p,
			Hops:           hops,
			CorrelatedHops: correlated,
			WeightBasis:    basis,
		}
		if isConf {
			v.Outcome = Confirmed
		}
		// Detection axis: reachable high-score paths are frequently caught (#7 signal).
		if scenario == "detection" && isConf && p >= 0.6 {
			caught := rng.Float64() < 0.7
			v.Detected = &caught
		}
		out = append(out, v)
	}
	return out, true
}
