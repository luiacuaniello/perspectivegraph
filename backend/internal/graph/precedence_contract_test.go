package graph_test

import (
	"context"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// assertAGuessNeverReplacesAFact: two sources can write the same edge, and when one of
// them stated it while the other guessed it, the last write used to win - so the step's
// probability depended on arrival order. Custodian, guessing an instance's role from its
// profile name, overwrote the network feed's stated 0.9 with 0.45 whenever it arrived
// second. A guess that lands on a fact now only refreshes the fact's last-seen stamp; a
// fact replaces a guess, and the labels that said it was one go with it.
func assertAGuessNeverReplacesAFact(t *testing.T, s graph.Store) {
	t.Helper()
	ctx := context.Background()
	t0 := time.Unix(1_790_000_000, 0)
	guessProps := func() map[string]any {
		return map[string]any{
			ontology.PropResolutionMethod:     "instance-profile-name",
			ontology.PropResolutionConfidence: 0.5,
		}
	}
	write := func(at time.Time, nodes []ontology.Node, e ontology.Edge) {
		t.Helper()
		if err := graph.ApplyEvent(ctx, s, ontology.Event{Source: "test", ObservedAt: at, Nodes: nodes,
			Edges: []ontology.Edge{e}}); err != nil {
			t.Fatalf("write %s %s->%s: %v", e.Type, e.From, e.To, err)
		}
	}
	edge := func(typ ontology.EdgeType, from, to string) ontology.Edge {
		t.Helper()
		snap, err := s.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range snap.Edges {
			if e.Type == typ && e.From == from && e.To == to {
				return e
			}
		}
		t.Fatalf("edge %s %s->%s missing", typ, from, to)
		return ontology.Edge{}
	}
	pair := func(prefix string) []ontology.Node {
		return []ontology.Node{
			{ID: prefix + "-vm", Label: ontology.LabelVirtualMachine, Name: prefix + "-vm"},
			{ID: prefix + "-role", Label: ontology.LabelIAMRole, Name: prefix + "-role"},
		}
	}

	// The first edge of its type in the graph is a guess: the check for a fact must not
	// trip over an edge type the store has never seen.
	write(t0, pair("first"), ontology.Edge{Type: ontology.EdgeHasPermission, From: "first-vm", To: "first-role",
		ExploitProbability: 0.4, Properties: guessProps()})
	if e := edge(ontology.EdgeHasPermission, "first-vm", "first-role"); !graph.Inferred(e) {
		t.Errorf("a guess on its own must be stored as one: %+v", e)
	}

	// Fact, then guess: the fact stays, and is seen again.
	write(t0, pair("fg"), ontology.Edge{Type: ontology.EdgeAssumes, From: "fg-vm", To: "fg-role", ExploitProbability: 0.9})
	write(t0.Add(time.Hour), nil, ontology.Edge{Type: ontology.EdgeAssumes, From: "fg-vm", To: "fg-role",
		ExploitProbability: 0.45, Properties: guessProps()})
	e := edge(ontology.EdgeAssumes, "fg-vm", "fg-role")
	if e.ExploitProbability < 0.89 || graph.Inferred(e) {
		t.Errorf("a guess replaced a fact: p=%.2f props=%v, want the stated 0.9 and no guess labels",
			e.ExploitProbability, e.Properties)
	}
	if ls, _ := graph.LastSeen(e.Properties); ls != t0.Add(time.Hour).Unix() {
		t.Errorf("last_seen = %d, want the guess's %d: the fact is still being reported", ls, t0.Add(time.Hour).Unix())
	}

	// Guess, then fact: the fact replaces it, guess labels and all.
	write(t0, pair("gf"), ontology.Edge{Type: ontology.EdgeAssumes, From: "gf-vm", To: "gf-role",
		ExploitProbability: 0.45, Properties: guessProps()})
	write(t0.Add(time.Hour), nil, ontology.Edge{Type: ontology.EdgeAssumes, From: "gf-vm", To: "gf-role", ExploitProbability: 0.9})
	e = edge(ontology.EdgeAssumes, "gf-vm", "gf-role")
	if e.ExploitProbability < 0.89 || graph.Inferred(e) || e.Properties[ontology.PropResolutionConfidence] != nil {
		t.Errorf("a fact did not replace a guess: p=%.2f props=%v", e.ExploitProbability, e.Properties)
	}

	// Between two facts, or two guesses, the newer observation still wins.
	write(t0.Add(2*time.Hour), nil, ontology.Edge{Type: ontology.EdgeAssumes, From: "gf-vm", To: "gf-role", ExploitProbability: 0.6})
	if e := edge(ontology.EdgeAssumes, "gf-vm", "gf-role"); e.ExploitProbability > 0.61 {
		t.Errorf("a newer fact must replace an older one: p=%.2f, want 0.6", e.ExploitProbability)
	}
	write(t0.Add(time.Hour), nil, ontology.Edge{Type: ontology.EdgeHasPermission, From: "first-vm", To: "first-role",
		ExploitProbability: 0.3, Properties: guessProps()})
	if e := edge(ontology.EdgeHasPermission, "first-vm", "first-role"); e.ExploitProbability > 0.31 {
		t.Errorf("a newer guess must replace an older one: p=%.2f, want 0.3", e.ExploitProbability)
	}

	// The rule holds for a single edge written outside an event, too.
	if err := s.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeAssumes, From: "gf-vm", To: "gf-role",
		ExploitProbability: 0.2, Properties: guessProps()}); err != nil {
		t.Fatal(err)
	}
	if e := edge(ontology.EdgeAssumes, "gf-vm", "gf-role"); e.ExploitProbability < 0.59 || graph.Inferred(e) {
		t.Errorf("UpsertEdge let a guess replace a fact: p=%.2f props=%v", e.ExploitProbability, e.Properties)
	}
}
