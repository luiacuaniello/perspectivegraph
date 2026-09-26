package semgrep

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const sample = `{
  "results": [
    {
      "check_id": "python.lang.security.audit.dangerous-subprocess-use.dangerous-subprocess-use",
      "path": "src/payments/handler.py",
      "start": { "line": 42 },
      "extra": {
        "message": "OS command injection",
        "severity": "ERROR",
        "metadata": { "cwe": ["CWE-78"], "category": "security", "confidence": "HIGH" }
      }
    },
    {
      "check_id": "generic.secrets.security.detected-aws-secret-access-key",
      "path": "src/payments/config.py",
      "start": { "line": 7 },
      "extra": {
        "message": "hardcoded AWS key",
        "severity": "ERROR",
        "metadata": { "category": "secrets", "confidence": "HIGH" }
      }
    }
  ]
}`

func TestParse(t *testing.T) {
	events, err := New().Parse(strings.NewReader(sample), ingestion.Options{Repository: "payments-api"})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]

	// 1 repository + 1 weakness + 1 secret = 3 nodes.
	if len(ev.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(ev.Nodes))
	}

	byLabel := map[ontology.Label]ontology.Node{}
	for _, n := range ev.Nodes {
		byLabel[n.Label] = n
	}
	if _, ok := byLabel[ontology.LabelRepository]; !ok {
		t.Error("missing Repository node")
	}
	w, ok := byLabel[ontology.LabelWeakness]
	if !ok {
		t.Fatal("missing Weakness node")
	}
	if w.Properties[ontology.PropSeverity] != "HIGH" {
		t.Errorf("weakness severity = %v, want HIGH (ERROR normalized)", w.Properties[ontology.PropSeverity])
	}
	if w.Properties["cwe"] != "CWE-78" {
		t.Errorf("weakness cwe = %v, want CWE-78", w.Properties["cwe"])
	}
	// The secrets-category rule must become a Secret, not a Weakness.
	if _, ok := byLabel[ontology.LabelSecret]; !ok {
		t.Error("secrets-category finding should map to a Secret node")
	}

	// Every finding edge originates from the repository with AFFECTS.
	repoID := ontology.NewID(ontology.LabelRepository, "payments-api")
	if len(ev.Edges) != 2 {
		t.Fatalf("expected 2 AFFECTS edges, got %d", len(ev.Edges))
	}
	for _, e := range ev.Edges {
		if e.Type != ontology.EdgeAffects || e.From != repoID {
			t.Errorf("unexpected edge %+v", e)
		}
	}

	// ERROR → HIGH on the shared cross-collector scale (0.7) × HIGH confidence.
	if got := exploitProbability("ERROR", "HIGH"); got != 0.7 {
		t.Errorf("exploitProbability(ERROR,HIGH) = %v, want 0.7", got)
	}
}

func TestDefaultRepository(t *testing.T) {
	events, err := New().Parse(strings.NewReader(sample), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := ontology.NewID(ontology.LabelRepository, "unknown-repo")
	if events[0].Nodes[0].ID != want {
		t.Errorf("default repo id = %s, want %s", events[0].Nodes[0].ID, want)
	}
}

// A report retracts the findings it no longer lists only when it describes a named
// repository in full: every unnamed report shares one default name, a file semgrep
// could not analyse has findings missing, and a pull request's scan describes a change.
func TestWhenASemgrepScanIsComplete(t *testing.T) {
	for _, tc := range []struct {
		name, report string
		opts         ingestion.Options
		want         string
	}{
		{"a named repository", `{"results":[],"errors":[]}`, ingestion.Options{Repository: "acme/api"}, "repository:acme/api"},
		{"an unnamed one", `{"results":[]}`, ingestion.Options{}, ""},
		{"a file it could not analyse", `{"results":[],"errors":[{"type":"ParseError"}]}`, ingestion.Options{Repository: "acme/api"}, ""},
		{"a pull request's scan", `{"results":[]}`, ingestion.Options{Repository: "acme/api", RepoSlug: "acme/api", PRNumber: 7}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := New().Parse(strings.NewReader(tc.report), tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if sn := evs[0].Snapshot; sn != nil {
				got = sn.Scope
			}
			if got != tc.want {
				t.Fatalf("scope %q, want %q", got, tc.want)
			}
		})
	}
}
