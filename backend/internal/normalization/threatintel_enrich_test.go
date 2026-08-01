package normalization

import (
	"context"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/threatintel"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// stubIntel serves a fixed intel table and records what was asked for, so a test can
// assert that only CVEs are looked up rather than every node in the event.
type stubIntel struct {
	table   map[string]threatintel.Intel
	enabled bool
	asked   []string
}

func (s *stubIntel) Enabled() bool { return s.enabled }
func (s *stubIntel) Scores(_ context.Context, cves []string) map[string]threatintel.Intel {
	s.asked = append(s.asked, cves...)
	out := map[string]threatintel.Intel{}
	for _, c := range cves {
		if in, ok := s.table[c]; ok {
			out[c] = in
		}
	}
	return out
}

func eventWithCVE() *ontology.Event {
	return &ontology.Event{
		Source: "trivy",
		Nodes: []ontology.Node{
			{ID: "img", Label: ontology.LabelImage, Name: "payments-api:1.4.2"},
			{ID: "cve", Label: ontology.LabelCVE, Name: "CVE-2021-44228"},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeAffects, From: "cve", To: "cve", ExploitProbability: 0.3},
		},
	}
}

// Threat intel is what turns a severity label into an exploitation fact, so the CVE
// node must come back carrying KEV and EPSS for the analyzer to weigh.
func TestEnrichStampsKEVAndEPSSOntoTheCVE(t *testing.T) {
	n := New(nil)
	n.WithThreatIntel(&stubIntel{enabled: true, table: map[string]threatintel.Intel{
		"CVE-2021-44228": {EPSS: 0.97, Percentile: 0.99, KEV: true},
	}})

	ev := eventWithCVE()
	n.enrichThreatIntel(context.Background(), ev)

	cve := ev.Nodes[1]
	if cve.Properties[ontology.PropKEV] != true {
		t.Errorf("KEV not stamped: %+v", cve.Properties)
	}
	if p, _ := cve.Properties[ontology.PropEPSS].(float64); p != 0.97 {
		t.Errorf("EPSS = %v, want 0.97", cve.Properties[ontology.PropEPSS])
	}
	if p, _ := cve.Properties[ontology.PropEPSSPercentile].(float64); p != 0.99 {
		t.Errorf("percentile = %v", cve.Properties[ontology.PropEPSSPercentile])
	}
}

// The AFFECTS edge is where the enrichment actually changes an attack path's score, and
// the basis has to travel with it - a hop weighted from KEV is evidence, one weighted
// from a severity label is an estimate, and the dashboard shows the difference.
func TestEnrichReweightsTheAffectsEdgeAndRecordsItsBasis(t *testing.T) {
	n := New(nil)
	n.WithThreatIntel(&stubIntel{enabled: true, table: map[string]threatintel.Intel{
		"CVE-2021-44228": {EPSS: 0.97, KEV: true},
	}})

	ev := eventWithCVE()
	before := ev.Edges[0].ExploitProbability
	n.enrichThreatIntel(context.Background(), ev)

	e := ev.Edges[0]
	if e.ExploitProbability <= before {
		t.Errorf("a KEV CVE left the edge at %v (was %v): the path score would not move", e.ExploitProbability, before)
	}
	if basis, _ := e.Properties[ontology.PropWeightBasis].(string); basis == "" {
		t.Error("no weight basis recorded, so the UI cannot tell evidence from estimate")
	}
}

// Disabled intel is the default configuration; it must leave the event exactly as it
// arrived rather than stamping zero values that look like measurements.
func TestEnrichIsANoOpWhenIntelIsDisabled(t *testing.T) {
	n := New(nil)
	s := &stubIntel{enabled: false, table: map[string]threatintel.Intel{"CVE-2021-44228": {KEV: true}}}
	n.WithThreatIntel(s)

	ev := eventWithCVE()
	n.enrichThreatIntel(context.Background(), ev)

	if len(s.asked) != 0 {
		t.Errorf("a disabled source was queried for %v", s.asked)
	}
	if _, present := ev.Nodes[1].Properties[ontology.PropKEV]; present {
		t.Error("a disabled source still stamped KEV, which would read as a measured false")
	}
}

// Only CVE nodes are looked up: sending every node name to the feed would leak asset
// names off the estate and waste the request.
func TestEnrichOnlyLooksUpCVEs(t *testing.T) {
	s := &stubIntel{enabled: true, table: map[string]threatintel.Intel{"CVE-2021-44228": {EPSS: 0.5}}}
	n := New(nil)
	n.WithThreatIntel(s)

	n.enrichThreatIntel(context.Background(), eventWithCVE())

	for _, asked := range s.asked {
		if asked != "CVE-2021-44228" {
			t.Errorf("looked up %q, which is not a CVE - asset names must not leave the estate", asked)
		}
	}
}

func TestEnrichHandlesAnEventWithNoCVEs(t *testing.T) {
	s := &stubIntel{enabled: true}
	n := New(nil)
	n.WithThreatIntel(s)

	ev := &ontology.Event{Nodes: []ontology.Node{{ID: "img", Label: ontology.LabelImage, Name: "x"}}}
	n.enrichThreatIntel(context.Background(), ev) // must not query or panic
	if len(s.asked) != 0 {
		t.Errorf("queried the feed for an event with no CVEs: %v", s.asked)
	}
}

// A CVE the feed does not know must be left alone rather than stamped with zeroes,
// which would present "no data" as "measured zero risk".
func TestEnrichLeavesUnknownCVEsUntouched(t *testing.T) {
	n := New(nil)
	n.WithThreatIntel(&stubIntel{enabled: true, table: map[string]threatintel.Intel{}})

	ev := eventWithCVE()
	n.enrichThreatIntel(context.Background(), ev)

	if _, present := ev.Nodes[1].Properties[ontology.PropEPSS]; present {
		t.Error("an unknown CVE was stamped with an EPSS value")
	}
}

// The option setters chain, or `New(m).WithX().WithY()` silently drops configuration.
func TestOptionSettersChain(t *testing.T) {
	n := New(nil)
	if n.WithThreatIntel(nil) != n || n.WithIndexer(nil) != n || n.WithScrub(true) != n {
		t.Fatal("an option setter did not return the normalizer")
	}
}
