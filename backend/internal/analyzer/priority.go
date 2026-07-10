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

	if p.RuntimeConfirmed {
		score += 0.22
		factors = append(factors, "runtime-confirmed (active)")
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
	switch {
	case p.Priority >= 70:
		p.PriorityLabel = "P1"
	case p.Priority >= 40:
		p.PriorityLabel = "P2"
	default:
		p.PriorityLabel = "P3"
	}
	p.PriorityFactors = factors
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
