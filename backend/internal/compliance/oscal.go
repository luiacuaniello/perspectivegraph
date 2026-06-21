// Package compliance renders PerspectiveGraph's attack-path findings as a NIST
// OSCAL Assessment Results document. Auditors and GRC tooling don't speak
// "attack path"; they speak controls. This layer is the translation: each
// reachable internet→crown-jewel path becomes an OSCAL observation (the
// evidence) plus a risk (the consequence), and each NIST 800-53 control those
// paths undermine becomes a not-satisfied finding linking back to them.
//
// The output validates as OSCAL 1.1.2 assessment-results. UUIDs are derived
// deterministically from the tenant + path identity, so re-exporting an
// unchanged posture yields a byte-identical document (diff-friendly, idempotent).
package compliance

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const ns = "https://perspectivegraph.dev/ns/oscal"

// ── OSCAL assessment-results subset (1.1.2) ─────────────────────────

type Document struct {
	AssessmentResults AssessmentResults `json:"assessment-results"`
}

type AssessmentResults struct {
	UUID     string   `json:"uuid"`
	Metadata Metadata `json:"metadata"`
	ImportAP ImportAP `json:"import-ap"`
	Results  []Result `json:"results"`
}

type Metadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

type ImportAP struct {
	Href string `json:"href"`
}

type Result struct {
	UUID         string        `json:"uuid"`
	Title        string        `json:"title"`
	Description  string        `json:"description"`
	Start        string        `json:"start"`
	Observations []Observation `json:"observations,omitempty"`
	Risks        []Risk        `json:"risks,omitempty"`
	Findings     []Finding     `json:"findings,omitempty"`
}

type Observation struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description"`
	Methods     []string `json:"methods"`
	Collected   string   `json:"collected"`
}

type Risk struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Statement   string `json:"statement"`
	Status      string `json:"status"`
	Props       []Prop `json:"props,omitempty"`
}

type Finding struct {
	UUID                string               `json:"uuid"`
	Title               string               `json:"title"`
	Description         string               `json:"description"`
	Target              Target               `json:"target"`
	RelatedObservations []RelatedObservation `json:"related-observations,omitempty"`
	RelatedRisks        []RelatedRisk        `json:"related-risks,omitempty"`
}

type Target struct {
	Type     string `json:"type"`
	TargetID string `json:"target-id"`
	Status   Status `json:"status"`
}

type Status struct {
	State string `json:"state"`
}

type Prop struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	NS    string `json:"ns,omitempty"`
}

type RelatedObservation struct {
	ObservationUUID string `json:"observation-uuid"`
}

type RelatedRisk struct {
	RiskUUID string `json:"risk-uuid"`
}

// ── control catalog (NIST SP 800-53 rev5) ───────────────────────────

var controlTitles = map[string]string{
	"sc-7":  "Boundary Protection",
	"ac-2":  "Account Management",
	"ac-6":  "Least Privilege",
	"ra-5":  "Vulnerability Monitoring and Scanning",
	"si-2":  "Flaw Remediation",
	"si-4":  "System Monitoring",
	"ir-4":  "Incident Handling",
	"sc-28": "Protection of Information at Rest",
	"cm-7":  "Least Functionality",
	"sa-11": "Developer Testing and Evaluation",
}

// controlsForPath maps a path's shape to the controls it undermines.
func controlsForPath(p analyzer.AttackPath) []string {
	set := map[string]bool{"sc-7": true} // every path crosses the internet boundary
	for _, n := range p.Nodes {
		switch n.Label {
		case ontology.LabelCVE:
			set["ra-5"], set["si-2"] = true, true
		case ontology.LabelMisconfiguration:
			set["cm-7"] = true
		case ontology.LabelWeakness:
			set["sa-11"] = true
		case ontology.LabelIAMRole, ontology.LabelUser, ontology.LabelServiceAccount:
			set["ac-6"] = true
		case ontology.LabelDatabase, ontology.LabelBucket:
			set["sc-28"] = true
		}
	}
	for _, s := range p.Steps {
		if s.EdgeType == ontology.EdgeCanEscalateTo {
			set["ac-6"], set["ac-2"] = true, true
		}
	}
	if p.RuntimeConfirmed {
		set["si-4"], set["ir-4"] = true, true
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Build renders the attack paths into an OSCAL assessment-results document. `now`
// is injected (not read from the clock) so the output is deterministic for tests
// and reproducible exports.
func Build(tenant string, paths []analyzer.AttackPath, now time.Time) Document {
	ts := now.UTC().Format(time.RFC3339)

	res := Result{
		UUID:        detUUID("result", tenant),
		Title:       "Attack-path assessment",
		Description: fmt.Sprintf("%d critical attack path(s) correlated by PerspectiveGraph for tenant %q.", len(paths), tenant),
		Start:       ts,
	}

	obsUUID := make([]string, len(paths))
	riskUUID := make([]string, len(paths))
	controlPaths := map[string][]int{}

	for i, p := range paths {
		obsUUID[i] = detUUID("obs", tenant, p.ID)
		riskUUID[i] = detUUID("risk", tenant, p.ID)
		route := pathRoute(p)

		res.Observations = append(res.Observations, Observation{
			UUID:  obsUUID[i],
			Title: fmt.Sprintf("Reachable attack path %s", p.ID),
			Description: fmt.Sprintf("Internet-exposed %q reaches crown jewel %q via: %s (exploit likelihood S=%.4f%s).",
				p.Source().Name, p.Target().Name, route, p.Score, runtimeNote(p)),
			Methods:   []string{"TEST"},
			Collected: ts,
		})
		res.Risks = append(res.Risks, Risk{
			UUID:        riskUUID[i],
			Title:       fmt.Sprintf("Crown jewel %q reachable from the internet", p.Target().Name),
			Description: fmt.Sprintf("A correlated attack path lets an internet attacker reach %q.", p.Target().Name),
			Statement:   route,
			Status:      "open",
			Props: []Prop{
				{Name: "likelihood", Value: likelihood(p.Score), NS: ns},
				{Name: "impact", Value: "high", NS: ns},
				{Name: "path-score", Value: fmt.Sprintf("%.4f", p.Score), NS: ns},
				{Name: "runtime-confirmed", Value: fmt.Sprintf("%t", p.RuntimeConfirmed), NS: ns},
			},
		})
		for _, c := range controlsForPath(p) {
			controlPaths[c] = append(controlPaths[c], i)
		}
	}

	for _, cid := range sortedKeys(controlPaths) {
		idxs := controlPaths[cid]
		relObs := make([]RelatedObservation, 0, len(idxs))
		relRisk := make([]RelatedRisk, 0, len(idxs))
		routes := make([]string, 0, len(idxs))
		for _, i := range idxs {
			relObs = append(relObs, RelatedObservation{ObservationUUID: obsUUID[i]})
			relRisk = append(relRisk, RelatedRisk{RiskUUID: riskUUID[i]})
			routes = append(routes, paths[i].ID)
		}
		res.Findings = append(res.Findings, Finding{
			UUID:                detUUID("finding", tenant, cid),
			Title:               fmt.Sprintf("%s (%s) not satisfied — undermined by %d attack path(s)", strings.ToUpper(cid), controlTitles[cid], len(idxs)),
			Description:         fmt.Sprintf("Control %s is undermined by attack paths: %s.", strings.ToUpper(cid), strings.Join(routes, ", ")),
			Target:              Target{Type: "objective-id", TargetID: cid + "_obj", Status: Status{State: "not-satisfied"}},
			RelatedObservations: relObs,
			RelatedRisks:        relRisk,
		})
	}

	return Document{AssessmentResults: AssessmentResults{
		UUID: detUUID("ar", tenant),
		Metadata: Metadata{
			Title:        fmt.Sprintf("PerspectiveGraph attack-path assessment — tenant %q", tenant),
			LastModified: ts,
			Version:      "1.0",
			OSCALVersion: "1.1.2",
		},
		ImportAP: ImportAP{Href: "urn:uuid:" + detUUID("ap", tenant)},
		Results:  []Result{res},
	}}
}

// ── helpers ─────────────────────────────────────────────────────────

func pathRoute(p analyzer.AttackPath) string {
	names := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		names = append(names, n.Name)
	}
	return strings.Join(names, " → ")
}

func likelihood(score float64) string {
	switch {
	case score >= 0.5:
		return "high"
	case score >= 0.2:
		return "moderate"
	default:
		return "low"
	}
}

func runtimeNote(p analyzer.AttackPath) string {
	if p.RuntimeConfirmed {
		return ", runtime-confirmed"
	}
	return ""
}

func sortedKeys(m map[string][]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// detUUID derives a stable RFC-4122 v4-formatted UUID from its parts, so an
// unchanged posture re-exports identically.
func detUUID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10x
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
