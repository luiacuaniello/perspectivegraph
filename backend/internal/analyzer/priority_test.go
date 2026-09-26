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
// that has no corroboration - the whole point of "signal, not noise".
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

// A fact about the route puts it in P1 whatever the blend says: the blend weighs
// exploitability at a third, and without a KEV entry an attacker walking into
// AdministratorAccess at that very moment read P2.
func TestAFactPutsARouteInP1(t *testing.T) {
	tagged := map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "tagged"}
	inferred := map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "inferred:customer"}
	direct := pathTo("open", 1, 0.5, false, false, "low", tagged)
	direct.DirectAccess = true
	for _, tc := range []struct {
		name string
		p    AttackPath
		p1   bool
	}{
		{"runtime alert, modest score", pathTo("rt", 0.3, 0.3, true, false, "low", inferred), true},
		{"open to anyone", direct, true},
		{"KEV on a likely route", pathTo("kev", 0.55, 0.3, false, true, "low", inferred), true},
		{"KEV on an unlikely route", pathTo("kev2", 0.2, 0.3, false, true, "low", inferred), false},
		{"likely, on evidence, valuable target", pathTo("lk", 0.85, 0.6, false, false, "medium", tagged), true},
		{"likely but assumed", pathTo("lk2", 0.95, 0.35, false, false, "low", tagged), false},
		{"likely into a guessed target", pathTo("lk3", 0.95, 0.6, false, false, "high", inferred), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := []AttackPath{tc.p}
			Prioritize(paths)
			got := paths[0]
			if (got.PriorityLabel == "P1") != tc.p1 {
				t.Fatalf("label %s (priority %.1f, reason %q), want P1=%v", got.PriorityLabel, got.Priority, got.PriorityReason, tc.p1)
			}
			if tc.p1 && (got.Priority < P1Floor || got.PriorityReason == "") {
				t.Errorf("a P1 by fact must carry the floor and say why: priority %.1f, reason %q", got.Priority, got.PriorityReason)
			}
		})
	}
}

// A test result re-bands a path where it is shown: confirmed to P1, refuted to P3 - but a
// refutation does not undo a runtime alert; the path says the evidence conflicts. The
// analyzer's own paths are not touched: they are cached, and the Priority a verdict is
// graded against must not already contain one.
func TestVerdictsReBandWhereShown(t *testing.T) {
	tagged := map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "tagged"}
	paths := []AttackPath{
		pathTo("top", 0.6, 0.5, false, false, "medium", tagged),
		pathTo("proven", 0.5, 0.5, false, false, "medium", tagged),
		pathTo("refuted", 0.6, 0.5, false, false, "medium", tagged),
		pathTo("live", 0.4, 0.5, true, false, "medium", tagged),
	}
	for i := range paths {
		paths[i].ID = paths[i].Source().ID
	}
	Prioritize(paths)
	before := map[string]float64{}
	for _, p := range paths {
		before[p.ID] = p.Priority
	}
	verdicts := map[string]Verdict{
		"proven": {"confirmed", "caldera"}, "refuted": {"refuted", "caldera"}, "live": {"refuted", "caldera"},
	}
	shown := ApplyVerdicts(paths, func(id string) (Verdict, bool) { v, ok := verdicts[id]; return v, ok })

	byID := map[string]AttackPath{}
	for _, p := range shown {
		byID[p.ID] = p
	}
	if p := byID["proven"]; p.PriorityLabel != "P1" || !hasFactor(p.PriorityFactors, "confirmed by caldera") {
		t.Errorf("confirmed: %s %v", p.PriorityLabel, p.PriorityFactors)
	}
	if p := byID["refuted"]; p.PriorityLabel != "P3" {
		t.Errorf("refuted: %s (%.1f)", p.PriorityLabel, p.Priority)
	}
	if p := byID["live"]; p.PriorityLabel != "P1" || !hasFactor(p.PriorityFactors, "evidence conflict: refuted by caldera") {
		t.Errorf("refuted but live: %s %v - a failed test does not undo a runtime alert", p.PriorityLabel, p.PriorityFactors)
	}
	for i := 1; i < len(shown); i++ {
		if shown[i].Priority > shown[i-1].Priority {
			t.Fatalf("not re-sorted: %v before %v", shown[i-1].ID, shown[i].ID)
		}
	}
	for _, p := range paths {
		if p.Priority != before[p.ID] || hasFactor(p.PriorityFactors, "confirmed by caldera") || hasFactor(p.PriorityFactors, "refuted by caldera") {
			t.Fatalf("the analyzer's path %s was modified: %.1f %v", p.ID, p.Priority, p.PriorityFactors)
		}
	}
}

// Inside a band the queue still has an order. Raising every fact's path to the floor left
// them all at exactly 70 - ten P1 routes with nothing to choose between them.
func TestP1KeepsAnOrder(t *testing.T) {
	tagged := map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "tagged"}
	strong := pathTo("strong", 0.9, 0.9, true, false, "high", tagged)
	weak := pathTo("weak", 0.2, 0.2, true, false, "low", tagged)
	paths := []AttackPath{weak, strong}
	Prioritize(paths)
	if paths[0].Source().ID != "strong" || paths[0].Priority <= paths[1].Priority {
		t.Fatalf("two runtime-confirmed paths tie or invert: strong %.1f, weak %.1f", find(paths, "strong").Priority, find(paths, "weak").Priority)
	}
	for _, p := range paths {
		if p.PriorityLabel != "P1" || p.Priority < P1Floor || p.Priority > 100 {
			t.Errorf("%s: %s %.1f", p.Source().ID, p.PriorityLabel, p.Priority)
		}
	}
}
