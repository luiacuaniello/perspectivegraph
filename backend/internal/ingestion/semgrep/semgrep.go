// Package semgrep converts a Semgrep JSON report (`semgrep --json`) into
// ontology events.
//
// Semgrep is a SAST tool: it finds code-level weaknesses (CWE-classified), not
// dependency CVEs. Each finding becomes a Weakness node (or a Secret node when
// the rule is a secrets rule) attached to the scanned Repository.
//
// Edge orientation follows attack progression (asset → vulnerability): an
// attacker who reaches a repository's deployed code reaches the weaknesses it
// contains. So edges run Repository --AFFECTS--> Weakness/Secret. The repository
// is linked into the wider graph by the build-provenance collector via Image --BUILT_FROM-->
// Repository, which is what lets a SAST finding land on a reachable attack path.
package semgrep

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// report is the subset of the Semgrep schema we consume.
type report struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"` // ERROR | WARNING | INFO
			Metadata struct {
				CWE        []string `json:"cwe"`
				OWASP      []string `json:"owasp"`
				Category   string   `json:"category"`   // e.g. "security", "secrets"
				Confidence string   `json:"confidence"` // HIGH | MEDIUM | LOW
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

type Collector struct {
	// defaultRepo is used when the webhook doesn't supply ?repo=.
	defaultRepo string
}

func New() *Collector             { return &Collector{defaultRepo: "unknown-repo"} }
func (*Collector) Source() string { return "semgrep" }

func (c *Collector) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	var rep report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode semgrep report: %w", err)
	}

	repoName := opts.Repository
	if repoName == "" {
		repoName = c.defaultRepo
	}
	repoID := ontology.NewID(ontology.LabelRepository, repoName)

	nodes := []ontology.Node{{
		ID:         repoID,
		Label:      ontology.LabelRepository,
		Name:       repoName,
		Properties: opts.PRProps(), // PR context for the action layer (may be nil)
	}}
	var edges []ontology.Edge
	seen := map[string]bool{}

	for _, res := range rep.Results {
		if res.CheckID == "" || res.Path == "" {
			continue
		}

		label := ontology.LabelWeakness
		if isSecret(res.CheckID, res.Extra.Metadata.Category) {
			label = ontology.LabelSecret
		}

		findingID := ontology.NewID(label, res.CheckID, res.Path, strconv.Itoa(res.Start.Line))
		if !seen[findingID] {
			seen[findingID] = true
			nodes = append(nodes, ontology.Node{
				ID:    findingID,
				Label: label,
				Name:  fmt.Sprintf("%s (%s:%d)", shortRule(res.CheckID), res.Path, res.Start.Line),
				Properties: map[string]any{
					ontology.PropSeverity: normalizeSeverity(res.Extra.Severity),
					"check_id":            res.CheckID,
					"path":                res.Path,
					"line":                res.Start.Line,
					"message":             truncate(res.Extra.Message, 240),
					"cwe":                 first(res.Extra.Metadata.CWE),
					"owasp":               first(res.Extra.Metadata.OWASP),
					"confidence":          res.Extra.Metadata.Confidence,
					"category":            res.Extra.Metadata.Category,
				},
			})
		}

		edges = append(edges, ontology.Edge{
			Type:               ontology.EdgeAffects,
			From:               repoID,
			To:                 findingID,
			ExploitProbability: exploitProbability(res.Extra.Severity, res.Extra.Metadata.Confidence),
		})
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindFinding,
		ObservedAt: time.Now().UTC(),
		Nodes:      nodes,
		Edges:      edges,
	}}, nil
}

func isSecret(checkID, category string) bool {
	return strings.EqualFold(category, "secrets") || strings.Contains(strings.ToLower(checkID), "secret")
}

// exploitProbability maps the normalized severity through the shared
// cross-collector scale, then discounts by Semgrep's rule confidence.
func exploitProbability(severity, confidence string) float64 {
	base := ingestion.SeverityProbability(normalizeSeverity(severity))
	var factor float64
	switch strings.ToUpper(confidence) {
	case "HIGH":
		factor = 1.0
	case "MEDIUM":
		factor = 0.85
	case "LOW":
		factor = 0.7
	default:
		factor = 0.85
	}
	return base * factor
}

// normalizeSeverity maps Semgrep's ERROR/WARNING/INFO onto the shared
// HIGH/MEDIUM/LOW scale used across collectors and the dashboard.
func normalizeSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "ERROR":
		return "HIGH"
	case "WARNING":
		return "MEDIUM"
	case "INFO":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// shortRule returns the last dotted segment of a Semgrep check_id.
func shortRule(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 && i < len(checkID)-1 {
		return checkID[i+1:]
	}
	return checkID
}

func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
