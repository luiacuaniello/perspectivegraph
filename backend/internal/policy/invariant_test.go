package policy

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestBuiltinInvariants(t *testing.T) {
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "alb",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "c", Label: ontology.LabelContainer, Name: "app"},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "admin",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
			{ID: "bucket", Label: ontology.LabelBucket, Name: "public-data",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeExposes, From: "lb", To: "c"},
			{Type: ontology.EdgeAssumes, From: "c", To: "role"},
		},
	}

	violations := NewEngine(Builtins()...).Evaluate(snap)

	got := map[string]Violation{}
	for _, v := range violations {
		got[v.InvariantID] = v
	}

	// Path invariant: lb -> c -> role should fire.
	v, ok := got["no-internet-to-sensitive-asset"]
	if !ok {
		t.Fatal("expected no-internet-to-sensitive-asset violation")
	}
	if len(v.Nodes) != 3 || v.Nodes[0].ID != "lb" || v.Nodes[2].ID != "role" {
		t.Errorf("unexpected violation path: %+v", v.Nodes)
	}

	// Node invariant: the public bucket should fire.
	if pb, ok := got["no-public-data-store"]; !ok {
		t.Error("expected no-public-data-store violation")
	} else if len(pb.Nodes) != 1 || pb.Nodes[0].ID != "bucket" {
		t.Errorf("unexpected public-data-store node: %+v", pb.Nodes)
	}

	// There is no Secret, so that invariant must NOT fire.
	if _, ok := got["no-internet-to-secret"]; ok {
		t.Error("did not expect a secret violation")
	}
}

func TestNoViolationsWhenSegmented(t *testing.T) {
	snap := graph.Snapshot{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "role", Label: ontology.LabelIAMRole, Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		// no edges connecting them
	}
	if v := NewEngine(Builtins()...).Evaluate(snap); len(v) != 0 {
		t.Fatalf("expected 0 violations, got %d: %+v", len(v), v)
	}
}

// A sensitive asset that is itself internet-exposed has no path to report - there is no
// edge to cross - so the path invariant never fired on it. Merely reachable, it is not
// counted as compromised either; this is where it is reported. Any label: the data-store
// invariant covers buckets and databases only.
func TestAnInternetExposedSensitiveAssetIsReported(t *testing.T) {
	snap := graph.Snapshot{Nodes: []ontology.Node{
		{ID: "vm", Label: ontology.LabelVirtualMachine, Name: "ledger-host",
			Properties: map[string]any{ontology.PropInternetExposed: true, ontology.PropCrownJewel: true}},
		{ID: "db", Label: ontology.LabelDatabase, Name: "internal",
			Properties: map[string]any{ontology.PropCrownJewel: true}},
		{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge",
			Properties: map[string]any{ontology.PropInternetExposed: true}},
	}}
	var hits []string
	for _, v := range NewEngine(Builtins()...).Evaluate(snap) {
		if v.InvariantID == "no-internet-exposed-sensitive-asset" {
			hits = append(hits, v.Nodes[0].ID)
		}
	}
	if len(hits) != 1 || hits[0] != "vm" {
		t.Errorf("violations on %v, want exactly the exposed sensitive VM", hits)
	}
}
