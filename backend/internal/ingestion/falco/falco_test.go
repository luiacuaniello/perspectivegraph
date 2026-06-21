package falco

import (
	"os"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestParseAlerts(t *testing.T) {
	f, err := os.Open("../../../testdata/falco-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	events, err := New().Parse(f, ingestion.Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ev := events[0]
	if ev.Kind != ontology.KindRuntime {
		t.Errorf("kind = %s, want runtime", ev.Kind)
	}

	// Two alerts on the same container collapse to one node...
	if len(ev.Nodes) != 1 {
		t.Fatalf("expected 1 container node, got %d", len(ev.Nodes))
	}
	n := ev.Nodes[0]
	if !n.Bool(ontology.PropRuntimeAlert) {
		t.Error("node should carry runtime_alert=true")
	}
	// ...keeping the highest-priority alert (Critical over Warning).
	if got := n.Properties[ontology.PropRuntimePriority]; got != "Critical" {
		t.Errorf("priority = %v, want Critical", got)
	}
	if got, _ := n.Properties[ontology.PropRuntimeRule].(string); !strings.Contains(got, "shell") {
		t.Errorf("rule = %v, want the shell rule", got)
	}

	// Its id must match the canonical container id so the runtime alert lands
	// on the same node other collectors describe.
	if want := ontology.NewID(ontology.LabelContainer, "payments"); n.ID != want {
		t.Errorf("container id = %s, want %s", n.ID, want)
	}
}

func TestParseNDJSON(t *testing.T) {
	nd := `{"rule":"r1","priority":"Warning","output_fields":{"container.name":"a"}}
{"rule":"r2","priority":"Critical","output_fields":{"container.name":"b"}}`
	events, err := New().Parse(strings.NewReader(nd), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events[0].Nodes) != 2 {
		t.Fatalf("expected 2 container nodes from NDJSON, got %d", len(events[0].Nodes))
	}
}

// A single pretty-printed alert (multi-line JSON) must decode like a compact one.
func TestParsePrettyPrintedAlert(t *testing.T) {
	pretty := `{
  "rule": "Terminal shell in container",
  "priority": "Notice",
  "output_fields": {
    "container.name": "payments"
  }
}`
	events, err := New().Parse(strings.NewReader(pretty), ingestion.Options{})
	if err != nil {
		t.Fatalf("pretty-printed alert rejected: %v", err)
	}
	if len(events) == 0 || len(events[0].Nodes) != 1 {
		t.Fatalf("expected 1 container node from pretty-printed alert, got %+v", events)
	}
}
