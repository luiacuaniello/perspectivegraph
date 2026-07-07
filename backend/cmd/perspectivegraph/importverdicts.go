package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// runImportVerdicts is the BAS → /validations bridge: it maps a tool-agnostic attack
// report onto the engine's live attack paths and records the verdicts, so a real
// red-team/BAS run (Pacu against CloudGoat, Caldera, a manual pentest) feeds the
// calibration loop with ZERO custom integration:
//
//	perspectivegraph importverdicts --file report.json --api http://localhost:8080
//
// The report is a small, tool-neutral JSON. Each finding either names a path id
// directly, or is matched to a live path by its target (crown-jewel name) and an
// optional entry (`from`), so a tester can report "I confirmed a path to
// account-admin" without knowing the engine's internal ids. `detected` on a confirmed
// finding feeds the detection axis (#7); `outcome:"missed"` records a false negative.
//
//	{
//	  "source": "pacu",
//	  "findings": [
//	    {"target": "account-admin", "from": "public-deployer", "outcome": "confirmed",
//	     "detected": false, "evidence": "iam privesc via CreatePolicyVersion"},
//	    {"target": "customers-db", "outcome": "refuted", "evidence": "SG blocks the DB"},
//	    {"route": "s3-public -> export", "outcome": "missed", "evidence": "not modeled"}
//	  ]
//	}
func runImportVerdicts(args []string) error {
	fs := flag.NewFlagSet("importverdicts", flag.ContinueOnError)
	file := fs.String("file", "", "BAS/Pacu-style report JSON (see runImportVerdicts)")
	api := fs.String("api", "http://localhost:8080", "API base URL")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token, if API auth is on")
	dryRun := fs.Bool("dry-run", false, "resolve and print verdicts without posting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("--file is required")
	}
	raw, err := os.ReadFile(*file) // #nosec G304 -- operator-supplied report path
	if err != nil {
		return err
	}
	var report struct {
		Source   string `json:"source"`
		Findings []struct {
			PathID   string `json:"pathId"`
			Target   string `json:"target"`
			From     string `json:"from"`
			Outcome  string `json:"outcome"`
			Detected *bool  `json:"detected"`
			Route    string `json:"route"`
			Evidence string `json:"evidence"`
			// Scope: "path" (default) grades this specific path's S(P); "target" grades
			// the per-target compromise probability - the right quantity when a BAS run
			// reports "I reached the crown jewel" by any route rather than "I walked
			// exactly this path".
			Scope string `json:"scope"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}
	if len(report.Findings) == 0 {
		return fmt.Errorf("report has no findings")
	}
	source := report.Source
	if source == "" {
		source = "bas-import"
	}

	client := &http.Client{Timeout: 30 * time.Second}
	paths, err := fetchPaths(client, *api, *token)
	if err != nil {
		return fmt.Errorf("fetch attack paths: %w", err)
	}

	posted, unmatched := 0, 0
	for _, f := range report.Findings {
		body := map[string]any{"outcome": f.Outcome, "source": source, "evidence": f.Evidence}
		if f.Scope != "" {
			body["scope"] = f.Scope
		}
		if f.Detected != nil {
			body["detected"] = *f.Detected
		}
		if f.Outcome == "missed" {
			body["route"] = f.Route // a false negative: no live path to reference
		} else {
			id, ok := resolvePath(paths, f.PathID, f.Target, f.From)
			if !ok {
				fmt.Printf("  ✗ no live path matches target=%q from=%q - skipped\n", f.Target, f.From)
				unmatched++
				continue
			}
			body["pathId"] = id
		}
		if *dryRun {
			b, _ := json.Marshal(body)
			fmt.Printf("  (dry-run) %s\n", b)
			posted++
			continue
		}
		b, _ := json.Marshal(body)
		st, rb, err := apiRequest(client, http.MethodPost, *api+"/validations", *token, b)
		if err != nil {
			return fmt.Errorf("post verdict: %w", err)
		}
		if st >= 300 {
			return fmt.Errorf("POST /validations returned %d: %s", st, string(rb))
		}
		posted++
	}

	fmt.Printf("importverdicts: recorded %d verdict(s), %d unmatched, from %s → %s\n", posted, unmatched, *file, *api)
	if !*dryRun {
		fmt.Printf("  read the diagnosis: curl -s %s/validations | jq '.calibration | {samples,verdict,diagnosis}'\n", *api)
	}
	return nil
}

// pathInfo is the live-path index the matcher walks: id plus the entry and target
// node names and the triage priority (to break ties).
type pathInfo struct {
	id, from, target string
	priority         float64
}

func fetchPaths(client *http.Client, api, token string) ([]pathInfo, error) {
	q := []byte(`{"query":"{ attackPaths { id priority nodes { name } } }"}`)
	st, rb, err := apiRequest(client, http.MethodPost, api+"/graphql", token, q)
	if err != nil {
		return nil, err
	}
	if st >= 300 {
		return nil, fmt.Errorf("graphql returned %d: %s", st, string(rb))
	}
	var resp struct {
		Data struct {
			AttackPaths []struct {
				ID       string  `json:"id"`
				Priority float64 `json:"priority"`
				Nodes    []struct {
					Name string `json:"name"`
				} `json:"nodes"`
			} `json:"attackPaths"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rb, &resp); err != nil {
		return nil, err
	}
	out := make([]pathInfo, 0, len(resp.Data.AttackPaths))
	for _, p := range resp.Data.AttackPaths {
		if len(p.Nodes) < 2 {
			continue
		}
		out = append(out, pathInfo{id: p.ID, from: p.Nodes[0].Name, target: p.Nodes[len(p.Nodes)-1].Name, priority: p.Priority})
	}
	return out, nil
}

// resolvePath maps a finding to a live path id: an explicit pathId wins; otherwise the
// highest-priority path whose target contains `target` (and, if given, whose entry
// contains `from`) - case-insensitive substring, so a tester's "account-admin" matches
// "account-admin (effective)". Reports false when nothing matches.
func resolvePath(paths []pathInfo, pathID, target, from string) (string, bool) {
	if pathID != "" {
		return pathID, true
	}
	if target == "" {
		return "", false
	}
	best, bestPri := "", -1.0
	for _, p := range paths {
		if !containsFold(p.target, target) {
			continue
		}
		if from != "" && !containsFold(p.from, from) {
			continue
		}
		if p.priority > bestPri {
			best, bestPri = p.id, p.priority
		}
	}
	return best, best != ""
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
