package analyzer

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// pathTo builds a 2-node path seed→jewel with the given signals, for priority tests.
func pathTo(seedID string, score, conf float64, runtime, kev bool, confLabel string, jewelProps map[string]any) AttackPath {
	seed := ontology.Node{ID: seedID, Label: ontology.LabelLoadBalancer, Name: seedID}
	if kev {
		seed.Properties = map[string]any{ontology.PropKEV: true}
	}
	jewel := ontology.Node{ID: "jewel-" + seedID, Label: ontology.LabelIAMRole, Name: "jewel", Properties: jewelProps}
	return AttackPath{
		Nodes: []ontology.Node{seed, jewel}, Score: score, Confidence: conf,
		RuntimeConfirmed: runtime, ConfidenceLabel: confLabel,
	}
}

func find(paths []AttackPath, seedID string) AttackPath {
	for _, p := range paths {
		if p.Source().ID == seedID {
			return p
		}
	}
	return AttackPath{}
}

// TestPrioritizeRanksAndLabels checks that the composite priority leads with the
// runtime-confirmed KEV path to classified PII over a higher *raw score* path
// that has no corroboration — the whole point of "signal, not noise".
func TestPrioritizeRanksAndLabels(t *testing.T) {
	classifiedPII := map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "classified:macie:pii", ontology.PropClassification: "pii"}
	inferred := map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "inferred:customer"}

	// a: modest score, but runtime + KEV + classified PII → should top the list.
	a := pathTo("a", 0.50, 0.9, true, true, "high", classifiedPII)
	// b: very high raw score, but no evidence and a weak (inferred) target.
	b := pathTo("b", 0.95, 0.35, false, false, "low", inferred)

	paths := []AttackPath{b, a} // deliberately worst-first
	Prioritize(paths)

	if paths[0].Source().ID != "a" {
		t.Fatalf("expected the runtime+KEV+PII path to lead, got %q (priorities: a=%.1f b=%.1f)",
			paths[0].Source().ID, find(paths, "a").Priority, find(paths, "b").Priority)
	}
	pa := find(paths, "a")
	if pa.PriorityLabel != "P1" {
		t.Errorf("path a label = %q, want P1 (priority %.1f)", pa.PriorityLabel, pa.Priority)
	}
	if !hasFactor(pa.PriorityFactors, "runtime-confirmed (active)") ||
		!hasFactor(pa.PriorityFactors, "KEV on path") ||
		!hasFactor(pa.PriorityFactors, "classified PII target") {
		t.Errorf("path a factors missing expected reasons: %v", pa.PriorityFactors)
	}
	if find(paths, "b").Priority >= pa.Priority {
		t.Errorf("the unsupported high-score path should rank below the corroborated one")
	}
}

// TestPriorityBlastRadius: an entry that opens several paths is weighted up.
func TestPriorityBlastRadius(t *testing.T) {
	jewel := map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "tagged"}
	// three paths share entry "shared", one path is alone.
	shared1 := pathTo("shared", 0.5, 0.5, false, false, "medium", jewel)
	shared2 := pathTo("shared", 0.5, 0.5, false, false, "medium", jewel)
	shared3 := pathTo("shared", 0.5, 0.5, false, false, "medium", jewel)
	lone := pathTo("lone", 0.5, 0.5, false, false, "medium", jewel)

	paths := []AttackPath{lone, shared1, shared2, shared3}
	Prioritize(paths)

	if find(paths, "shared").Priority <= find(paths, "lone").Priority {
		t.Errorf("a shared entry (blast radius) should raise priority over an identical lone path")
	}
	if !hasFactor(find(paths, "shared").PriorityFactors, "entry shared by 3 paths") {
		t.Errorf("blast-radius factor missing: %v", find(paths, "shared").PriorityFactors)
	}
}

func hasFactor(factors []string, want string) bool {
	for _, f := range factors {
		if f == want {
			return true
		}
	}
	return false
}
