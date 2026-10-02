package main

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/redteam"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The comparison grades the engine only on questions the oracle actually answered. A claim
// the engine itself qualified - held on specific resources only, or blocked under a
// condition it cannot evaluate - is not refuted by AWS's answer for one context.
func TestGradeSettlesOnlyComparableClaims(t *testing.T) {
	for _, c := range []struct {
		name    string
		claim   claim
		aws     redteam.Decision
		mark    string
		outcome int
	}{
		{"never collected", claim{}, redteam.Denied, "unsettled", outcomeUnsettled},
		{"oracle could not settle", claim{collected: true, escalates: true}, redteam.Inconclusive, "unsettled", outcomeUnsettled},
		{"both escalate", claim{collected: true, escalates: true}, redteam.Allowed, "agree", outcomeAgree},
		{"neither escalates", claim{collected: true}, redteam.Denied, "agree", outcomeAgree},
		{"false positive", claim{collected: true, escalates: true}, redteam.Denied, "DISAGREE", outcomeDisagree},
		{"miss", claim{collected: true}, redteam.Allowed, "DISAGREE", outcomeDisagree},
		{"scoped, refused account-wide", claim{collected: true, escalates: true, scoped: true}, redteam.Denied, "unsettled (scoped)", outcomeUnsettled},
		{"conditional, refused in one context", claim{collected: true, escalates: true, conditional: true}, redteam.Denied, "unsettled (conditional)", outcomeUnsettled},
		{"conditional, allowed anyway", claim{collected: true, escalates: true, conditional: true}, redteam.Allowed, "agree", outcomeAgree},
	} {
		if _, mark, outcome := grade(c.claim, c.aws); mark != c.mark || outcome != c.outcome {
			t.Errorf("%s: mark %q outcome %d, want %q %d", c.name, mark, outcome, c.mark, c.outcome)
		}
	}
}

// The claims are read off the engine's own edges, qualifiers included.
func TestEngineEscalationsReadsTheQualifiers(t *testing.T) {
	ev := ontology.Event{
		Nodes: []ontology.Node{
			{ID: "r1", Properties: map[string]any{ontology.PropARN: "arn:aws:iam::1:role/conditional"}},
			{ID: "r2", Properties: map[string]any{ontology.PropARN: "arn:aws:iam::1:role/plain"}},
			{ID: "r3", Properties: map[string]any{ontology.PropARN: "arn:aws:iam::1:role/none"}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeCanEscalateTo, From: "r1", To: "admin", Properties: map[string]any{"deny_condition_unevaluated": true}},
			{Type: ontology.EdgeCanEscalateTo, From: "r2", To: "admin"},
		},
	}
	got := engineEscalations([]ontology.Event{ev})
	if c := got["arn:aws:iam::1:role/conditional"]; !c.collected || !c.escalates || !c.conditional {
		t.Errorf("conditional claim read as %+v", c)
	}
	if c := got["arn:aws:iam::1:role/plain"]; !c.escalates || c.conditional || c.scoped {
		t.Errorf("plain claim read as %+v", c)
	}
	if c := got["arn:aws:iam::1:role/none"]; !c.collected || c.escalates {
		t.Errorf("a collected principal with no edge read as %+v", c)
	}
}
