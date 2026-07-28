package analyzer

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The crown-jewel lab.
//
// What makes a node worth attacking is, for most operators, a tag - and a tag is
// attacker-writable: `ec2:CreateTags` is granted freely because tagging looks harmless.
// So the attacker this tool exists to detect can promote junk into the crown-jewel set,
// manufacturing paths that dilute a board whose entire promise is "~5 routes that
// matter, not 10,000 findings".
//
// The engine already ranks crown-jewel provenance - an authoritative classifier outranks
// a tag outranks a name heuristic - and that ranking is the right answer. These tests pin
// it, and pin the part that was missing: a tag-derived jewel has to be RECORDED as
// tag-derived, or the distinction never reaches the ranking that depends on it.

func jewel(basis, classification string) ontology.Node {
	props := map[string]any{ontology.PropCrownJewel: true}
	if basis != "" {
		props[ontology.PropCrownJewelBasis] = basis
	}
	if classification != "" {
		props[ontology.PropClassification] = classification
	}
	return ontology.Node{ID: "t", Name: "target", Label: ontology.LabelDatabase, Properties: props}
}

// An authoritative classifier is the only crown-jewel signal an attacker with tagging
// rights cannot forge, so it must outrank the ones they can.
func TestClassifiedTargetOutranksAnythingAttackerWritable(t *testing.T) {
	classified, _ := jewelWeight(jewel("classified:macie:pii", "pii"))
	tagged, _ := jewelWeight(jewel("tagged", ""))
	inferred, _ := jewelWeight(jewel("inferred:name", ""))

	if !(classified > tagged) {
		t.Errorf("a Macie-classified target (%.2f) must outrank a tagged one (%.2f)", classified, tagged)
	}
	if !(tagged > inferred) {
		t.Errorf("an explicit tag (%.2f) must outrank a name guess (%.2f)", tagged, inferred)
	}
}

// The gap this lab was built for. A jewel that exists only because someone wrote a tag
// must arrive carrying that fact: the ranking above reads the basis, so a tag-derived
// jewel with no basis silently takes the default weight and the distinction the design
// depends on never happens.
func TestTagDerivedJewelIsRankedAsTagDerived(t *testing.T) {
	w, label := jewelWeight(jewel("tagged", ""))
	if w != 0.7 {
		t.Errorf("weight for a tagged jewel = %.2f, want 0.7", w)
	}
	if !strings.Contains(label, "tagged") {
		t.Errorf("the operator must be told the target is only tag-deep, got %q", label)
	}
}

// A jewel whose provenance was never recorded is indistinguishable from one that was
// classified by a real tool. Whatever weight it gets, it must not be the top one - the
// engine cannot claim authority it did not observe.
func TestUnprovenancedJewelDoesNotGetAuthoritativeWeight(t *testing.T) {
	unknown, _ := jewelWeight(jewel("", ""))
	classified, _ := jewelWeight(jewel("classified:macie:pii", "pii"))
	if unknown >= classified {
		t.Errorf("a jewel with unknown provenance (%.2f) must rank below a classified one (%.2f)",
			unknown, classified)
	}
}

// The label is what the operator reads in the priority factors. A weight with no
// explanation is a number to argue with; a weight that says "tagged sensitive asset"
// tells them the finding rests on something anyone with tagging rights can write.
func TestEveryJewelWeightExplainsItself(t *testing.T) {
	for _, basis := range []string{"classified:macie:pii", "tagged", "inferred:name", ""} {
		w, label := jewelWeight(jewel(basis, ""))
		if w > 0 && label == "" {
			t.Errorf("basis %q scored %.2f with no explanation", basis, w)
		}
	}
}
