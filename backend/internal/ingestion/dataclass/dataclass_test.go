package dataclass

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const sample = `{"source":"macie","records":[
  {"asset":"customer-exports","kind":"PII"},
  {"asset":"payments-db","label":"Database","kind":"pci","source":"dlp"},
  {"asset":"","kind":"pii"},
  {"asset":"x","kind":""}
]}`

func TestParse(t *testing.T) {
	events, err := New().Parse(strings.NewReader(sample), ingestion.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Source != "dataclass" || ev.Kind != ontology.KindAsset {
		t.Errorf("source/kind = %q/%q", ev.Source, ev.Kind)
	}
	// Only the two complete records become nodes; empty asset / empty kind skipped.
	if len(ev.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(ev.Nodes))
	}

	byID := map[string]ontology.Node{}
	for _, n := range ev.Nodes {
		byID[n.ID] = n
	}

	bucket := byID[ontology.NewID(ontology.LabelBucket, "customer-exports")]
	if bucket.Label != ontology.LabelBucket {
		t.Errorf("default label should be Bucket, got %q", bucket.Label)
	}
	if bucket.Properties[ontology.PropClassification] != "pii" {
		t.Errorf("classification = %v, want lower-cased 'pii'", bucket.Properties[ontology.PropClassification])
	}
	if bucket.Properties[ontology.PropCrownJewelBasis] != "classified:macie:pii" {
		t.Errorf("basis = %v, want classified:macie:pii", bucket.Properties[ontology.PropCrownJewelBasis])
	}

	db := byID[ontology.NewID(ontology.LabelDatabase, "payments-db")]
	if db.Label != ontology.LabelDatabase {
		t.Errorf("explicit Database label not honoured: %q", db.Label)
	}
	if db.Properties[ontology.PropCrownJewelBasis] != "classified:dlp:pci" {
		t.Errorf("per-record source override lost: %v", db.Properties[ontology.PropCrownJewelBasis])
	}
}

func TestParseErrors(t *testing.T) {
	for name, body := range map[string]string{
		"empty":       ``,
		"not json":    `<<x>>`,
		"no records":  `{"records":[]}`,
		"all skipped": `{"records":[{"asset":"","kind":""}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New().Parse(strings.NewReader(body), ingestion.Options{}); err == nil {
				t.Errorf("expected an error for %q", name)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add(``)
	f.Add(`{`)
	f.Add(`{"records":[{"asset":"a","label":"Database","kind":"pii"}]}`)
	c := New()
	f.Fuzz(func(t *testing.T, data string) {
		events, err := c.Parse(strings.NewReader(data), ingestion.Options{})
		if err != nil {
			return
		}
		for _, ev := range events {
			for _, n := range ev.Nodes {
				if n.ID == "" || !ontology.IsValidLabel(n.Label) {
					t.Fatalf("emitted malformed node: %+v", n)
				}
			}
		}
	})
}
