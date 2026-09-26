package analyzer

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Prioritize assigns every path a composite triage priority and re-orders the
// slice so the highest-priority risks lead - the "what do I fix first?" view that
// turns a wall of paths into an actionable Top-N.
//
// The raw exploit Score answers "how easy", but a 2-person team needs "how
// MUCH should I care", which also depends on corroboration (runtime / KEV /
// confidence), what's at the end (a classified-PII jewel vs an inferred one), and
// leverage (an entry that opens many paths). Priority blends those into one
// number in [0,100]. Blast radius is measured across the whole set, so this runs
// on the full result, not per path.
//
// The weights below sum to 1.0:
//
//	0.35 exploitability (Score)      0.10 KEV weakness on the route
//	0.15 trust in the score (Confidence)  0.13 target sensitivity
//	0.22 runtime-confirmed (active)  0.05 entry blast radius
//
// A direct-access path - a crown jewel open to anyone - takes the runtime weight: like
// a live alert it is not a prediction but a present fact, the data is readable now. The
// two do not add up; one path is either, and the total is capped at 1 regardless.
func Prioritize(paths []AttackPath) {
	entryBlast := make(map[string]int, len(paths))
	for i := range paths {
		entryBlast[paths[i].Source().ID]++
	}
	for i := range paths {
		paths[i].setPriority(entryBlast[paths[i].Source().ID])
	}
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Priority != paths[j].Priority {
			return paths[i].Priority > paths[j].Priority
		}
		return paths[i].Score > paths[j].Score
	})
}

func (p *AttackPath) setPriority(blast int) {
	score := 0.35*p.Score + 0.15*p.Confidence
	var factors []string

	switch {
	case p.RuntimeConfirmed:
		score += 0.22
		factors = append(factors, "runtime-confirmed (active)")
	case p.DirectAccess:
		score += 0.22
		factors = append(factors, "open to anyone (no exploit needed)")
	}
	if p.kevOnPath() {
		score += 0.10
		factors = append(factors, "KEV on path")
	}
	if jw, label := jewelWeight(p.Target()); jw > 0 {
		score += 0.13 * jw
		if label != "" {
			factors = append(factors, label)
		}
	}
	if blast > 1 {
		bn := math.Min(1, float64(blast-1)/4)
		score += 0.05 * bn
		factors = append(factors, fmt.Sprintf("entry shared by %d paths", blast))
	}
	if p.ConfidenceLabel == "high" {
		factors = append(factors, "evidence-backed")
	}

	score = math.Min(1, score)
	p.Priority = math.Round(score*1000) / 10 // [0,100], 1 decimal
	p.PriorityFactors = factors
	p.PriorityReason = p.p1Fact()
	if p.PriorityReason != "" || p.Priority >= P1Floor {
		p.Priority = liftToP1(p.Priority)
	}
	p.PriorityLabel = bandOf(p.Priority)
}

// P1Floor is where P1 starts.
const P1Floor = 70

// liftToP1 maps a blended priority into the P1 band, keeping its order: every P1 path -
// by fact or by blend - sits in [70, 100] at 70 plus 30% of its blend. Raising a fact's
// path to the floor instead left every one of them at exactly 70, a band with no order in
// it; and the number and the band still never disagree, so the queue is one sort.
func liftToP1(blended float64) float64 {
	return math.Round((P1Floor+(100-P1Floor)*blended/100)*10) / 10
}

// sinkToP3 maps a priority into the P3 band, keeping its order: where a refuted path goes.
func sinkToP3(priority float64) float64 {
	return math.Round(priority*0.399*10) / 10
}

func bandOf(priority float64) string {
	switch {
	case priority >= P1Floor:
		return "P1"
	case priority >= 40:
		return "P2"
	default:
		return "P3"
	}
}

// p1Fact is the reason a path is P1 whatever its blended priority says, or "".
//
// The blend weighs exploitability at a third, so it could not reach P1 without a KEV
// entry: a route an attacker was walking at that moment, into AdministratorAccess, read
// P2. No security team triages that way. Each case below is a fact about the route,
// not an estimate, and each one alone is what a team drops everything for:
//
//   - a runtime sensor fired on it: it is happening, not predicted;
//   - the asset is open to anyone: nothing needs exploiting;
//   - a known-exploited (KEV) weakness sits on a route an attacker is likely to walk;
//   - the route is likely (≥80%), the evidence behind that is not merely assumed, and
//     what it reaches is worth reaching - not a sensitive asset guessed from its name.
//
// The last keeps the rule the blend was built on: a high score that rests on assumed
// weights, into an inferred target, is not by itself a reason to drop everything.
func (p *AttackPath) p1Fact() string {
	switch {
	case p.RuntimeConfirmed:
		return "a runtime alert fired on this route: it is happening, not predicted"
	case p.DirectAccess:
		return "the asset is open to anyone: there is nothing to exploit"
	case p.kevOnPath() && p.Score >= 0.5:
		return "a known-exploited (KEV) weakness sits on a route an attacker is likely to complete"
	}
	if jw, _ := jewelWeight(p.Target()); p.Score >= 0.8 && jw >= 0.6 &&
		(p.ConfidenceLabel == "medium" || p.ConfidenceLabel == "high") {
		return fmt.Sprintf("an attacker is likely (%.0f%%) to complete this route, on evidence rather than assumption, into a high-value asset", p.Score*100)
	}
	return ""
}

// Verdict is a red-team or BAS test result on a path, as ApplyVerdicts reads it.
type Verdict struct {
	Outcome string // confirmed | refuted | partial
	Source  string
}

// ApplyVerdicts returns paths re-banded by the test results recorded on them, re-sorted.
//
// A route a red team walked end to end is P1: that is what the test proves. One it could
// not walk drops to P3 - unless a runtime alert fired on it or it is open to anyone,
// facts a failed test cannot undo; the path then says the evidence conflicts.
//
// It is applied where paths are shown, never in the analyzer: the Priority a verdict is
// graded against (validation.Record.PredictedPriority) must not already contain a verdict,
// or the triage-order AUC would grade the ranking on the answers it was given.
func ApplyVerdicts(paths []AttackPath, verdictOf func(pathID string) (Verdict, bool)) []AttackPath {
	out := make([]AttackPath, len(paths))
	copy(out, paths)
	changed := false
	for i := range out {
		v, ok := verdictOf(out[i].ID)
		if !ok {
			continue
		}
		p := &out[i]
		src := v.Source
		if src == "" {
			src = "a test"
		}
		switch v.Outcome {
		case "confirmed":
			p.PriorityFactors = append(append([]string(nil), p.PriorityFactors...), "confirmed by "+src)
			if p.Priority < P1Floor {
				p.Priority = liftToP1(p.Priority)
				p.PriorityReason = src + " walked this route end to end"
			}
		case "refuted":
			if p.RuntimeConfirmed || p.DirectAccess {
				p.PriorityFactors = append(append([]string(nil), p.PriorityFactors...),
					"evidence conflict: refuted by "+src)
				if p.RuntimeConfirmed {
					p.PriorityReason = "the evidence conflicts - a runtime alert fired on this route, but " + src + " could not walk it"
				} else {
					p.PriorityReason = "the evidence conflicts - the asset is open to anyone, but " + src + " could not reach it"
				}
				continue
			}
			p.PriorityFactors = append(append([]string(nil), p.PriorityFactors...), "refuted by "+src)
			p.Priority = sinkToP3(p.Priority)
			p.PriorityReason = src + " could not walk this route"
		case "partial":
			p.PriorityFactors = append(append([]string(nil), p.PriorityFactors...), "partly walked by "+src)
		default:
			continue
		}
		p.PriorityLabel = bandOf(p.Priority)
		changed = true
	}
	if changed {
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Priority != out[j].Priority {
				return out[i].Priority > out[j].Priority
			}
			return out[i].Score > out[j].Score
		})
	}
	return out
}

// kevOnPath reports whether any node on the route carries a CISA-KEV weakness -
// a known-exploited vulnerability, the strongest "this is real" signal short of a
// live runtime alert.
func (p AttackPath) kevOnPath() bool {
	for _, n := range p.Nodes {
		if n.Bool(ontology.PropKEV) {
			return true
		}
	}
	return false
}

// jewelWeight scores how much the target is worth stealing, from its crown-jewel
// provenance: an authoritative data classification outranks an explicit tag,
// which outranks a name-heuristic guess. Returns the weight [0,1] and a label.
func jewelWeight(target ontology.Node) (float64, string) {
	basis, _ := target.Properties[ontology.PropCrownJewelBasis].(string)
	cls, _ := target.Properties[ontology.PropClassification].(string)
	switch {
	case strings.HasPrefix(basis, "classified"):
		if cls != "" {
			return 1.0, "classified " + strings.ToUpper(cls) + " target"
		}
		return 1.0, "classified target"
	case basis == "tagged":
		return 0.7, "tagged sensitive asset"
	case strings.HasPrefix(basis, "inferred"):
		return 0.4, "inferred sensitive asset"
	default:
		if target.Bool(ontology.PropCrownJewel) {
			return 0.6, "sensitive asset target"
		}
		return 0, ""
	}
}
