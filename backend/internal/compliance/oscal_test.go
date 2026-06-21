package compliance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func samplePaths() []analyzer.AttackPath {
	return []analyzer.AttackPath{
		{
			ID:    "ap-lb-role",
			Score: 0.36,
			Nodes: []ontology.Node{
				{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb"},
				{ID: "c1", Label: ontology.LabelContainer, Name: "payments"},
				{ID: "cve", Label: ontology.LabelCVE, Name: "CVE-2021-44228"},
				{ID: "role", Label: ontology.LabelIAMRole, Name: "admin"},
			},
			Steps: []analyzer.Step{
				{EdgeType: ontology.EdgeExposes, From: "lb", To: "c1"},
				{EdgeType: ontology.EdgeAffects, From: "c1", To: "cve"},
				{EdgeType: ontology.EdgeExploits, From: "cve", To: "role"},
			},
			RuntimeConfirmed: true,
		},
	}
}

func TestBuildProducesValidOSCAL(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	doc := Build("acme", samplePaths(), now)

	if doc.AssessmentResults.Metadata.OSCALVersion != "1.1.2" {
		t.Errorf("oscal-version = %q, want 1.1.2", doc.AssessmentResults.Metadata.OSCALVersion)
	}
	if len(doc.AssessmentResults.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(doc.AssessmentResults.Results))
	}
	res := doc.AssessmentResults.Results[0]
	if len(res.Observations) != 1 || len(res.Risks) != 1 {
		t.Fatalf("expected 1 observation and 1 risk, got %d / %d", len(res.Observations), len(res.Risks))
	}

	controls := map[string]Finding{}
	for _, f := range res.Findings {
		controls[f.Target.TargetID] = f
	}
	// A CVE on the path implicates ra-5 + si-2; an IAM role implicates ac-6;
	// every path implicates sc-7; runtime confirmation implicates si-4 + ir-4.
	for _, want := range []string{"sc-7_obj", "ra-5_obj", "si-2_obj", "ac-6_obj", "si-4_obj", "ir-4_obj"} {
		f, ok := controls[want]
		if !ok {
			t.Errorf("missing finding for control objective %s", want)
			continue
		}
		if f.Target.Status.State != "not-satisfied" {
			t.Errorf("%s state = %q, want not-satisfied", want, f.Target.Status.State)
		}
		if len(f.RelatedObservations) == 0 || len(f.RelatedRisks) == 0 {
			t.Errorf("%s should link to observations and risks", want)
		}
		if f.RelatedObservations[0].ObservationUUID != res.Observations[0].UUID {
			t.Errorf("%s related-observation UUID mismatch", want)
		}
	}

	// It must serialize to JSON with OSCAL's kebab-case keys.
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"assessment-results"`, `"oscal-version"`, `"related-observations"`, `"target-id"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("serialized OSCAL missing key %s", key)
		}
	}
}

func TestBuildDeterministic(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	a, _ := json.Marshal(Build("acme", samplePaths(), now))
	b, _ := json.Marshal(Build("acme", samplePaths(), now))
	if string(a) != string(b) {
		t.Error("Build must be deterministic for an unchanged posture")
	}
	// Different tenant → different document UUID.
	if Build("acme", samplePaths(), now).AssessmentResults.UUID == Build("globex", samplePaths(), now).AssessmentResults.UUID {
		t.Error("different tenants must yield different assessment UUIDs")
	}
}
