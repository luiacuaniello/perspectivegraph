package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func bigEvent(nodes, edges int) ontology.Event {
	ev := ontology.Event{Source: "k8s", Kind: ontology.KindAsset, Tenant: "acme",
		ObservedAt: time.Unix(1_700_000_000, 0).UTC()}
	for i := 0; i < nodes; i++ {
		ev.Nodes = append(ev.Nodes, ontology.Node{ID: fmt.Sprintf("n-%d", i), Label: ontology.LabelContainer,
			Name: fmt.Sprintf("workload-%d", i), Properties: map[string]any{"ns": "prod", "i": float64(i)}})
	}
	for i := 0; i < edges; i++ {
		ev.Edges = append(ev.Edges, ontology.Edge{Type: ontology.EdgeConnectsTo,
			From: fmt.Sprintf("n-%d", i), To: fmt.Sprintf("n-%d", (i+1)%nodes), ExploitProbability: 0.5})
	}
	return ev
}

// A split event is the same event: every chunk fits, carries the original's source,
// kind, time and tenant, and the chunks together hold every node and edge, in order,
// nodes first.
func TestSplitEventKeepsEverythingAndFits(t *testing.T) {
	ev := bigEvent(300, 250)
	const limit = 4096
	chunks, err := splitEvent(ev, limit)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 3 {
		t.Fatalf("%d chunks for a %d-node event under %d bytes; want several", len(chunks), len(ev.Nodes), limit)
	}
	var nodes []ontology.Node
	var edges []ontology.Edge
	seenEdges := false
	for i, c := range chunks {
		if len(c) > limit {
			t.Errorf("chunk %d is %d bytes, over the %d limit", i, len(c), limit)
		}
		var got ontology.Event
		if err := json.Unmarshal(c, &got); err != nil {
			t.Fatal(err)
		}
		if got.Source != ev.Source || got.Kind != ev.Kind || got.Tenant != ev.Tenant || !got.ObservedAt.Equal(ev.ObservedAt) {
			t.Errorf("chunk %d lost the event's metadata: %+v", i, got)
		}
		if len(got.Nodes) > 0 && seenEdges {
			t.Errorf("chunk %d carries nodes after edges were sent", i)
		}
		seenEdges = seenEdges || len(got.Edges) > 0
		nodes = append(nodes, got.Nodes...)
		edges = append(edges, got.Edges...)
	}
	var want ontology.Event
	whole, _ := json.Marshal(ev)
	_ = json.Unmarshal(whole, &want)
	if !reflect.DeepEqual(nodes, want.Nodes) || !reflect.DeepEqual(edges, want.Edges) {
		t.Errorf("the chunks do not add up to the event: %d/%d nodes, %d/%d edges", len(nodes), len(want.Nodes), len(edges), len(want.Edges))
	}
}

func TestSplitEventLeavesASmallEventWhole(t *testing.T) {
	ev := bigEvent(3, 2)
	chunks, err := splitEvent(ev, 1<<20)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("chunks=%d err=%v, want one", len(chunks), err)
	}
	whole, _ := json.Marshal(ev)
	if string(chunks[0]) != string(whole) {
		t.Error("a small event was re-encoded differently")
	}
}

// One element that cannot fit alone is refused with an error that says so, rather than
// sent to fail at the server with a message about payloads.
func TestSplitEventRefusesAnElementLargerThanAMessage(t *testing.T) {
	ev := bigEvent(2, 0)
	ev.Nodes[0].Properties["blob"] = strings.Repeat("x", 10_000)
	if _, err := splitEvent(ev, 4096); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}
