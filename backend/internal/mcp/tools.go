package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The tools are deliberately few. An agent plans better against eight sharp
// capabilities than against the API's two hundred fields, and every tool here
// answers a question the model cannot answer by itself: what routes exist, what
// they traverse, what cutting an edge would do. Anything the model can reason out
// from those answers is left to the model.

// API is a thin GraphQL client against a running PerspectiveGraph. Going through
// the public API (rather than the graph store) means the MCP server inherits
// tenancy, auth and the exact scoring the dashboard sees - one engine, one answer.
type API struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewAPI builds a client with a bounded timeout: an agent waiting on a tool call
// is a stalled conversation, so a slow environment must fail rather than hang.
func NewAPI(baseURL, token string) *API {
	return &API{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (a *API) query(ctx context.Context, q string, out any) error {
	body, err := json.Marshal(map[string]string{"query": q})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.BaseURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("the engine is unreachable at %s: %w", a.BaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("engine returned HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("engine returned a non-GraphQL response")
	}
	if len(envelope.Errors) > 0 {
		return fmt.Errorf("engine rejected the query: %s", envelope.Errors[0].Message)
	}
	return json.Unmarshal(envelope.Data, out)
}

// Tools is the curated capability set, ordered as an agent should meet them:
// orient, then enumerate, then inspect, then simulate.
func Tools(api *API) []Tool {
	return []Tool{
		posture(api),
		listPaths(api),
		explainPath(api),
		routesToTarget(api),
		listFixes(api),
		simulateFix(api),
		searchAssets(api),
		scoreTrust(api),
	}
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func posture(api *API) Tool {
	return Tool{
		Name: "get_posture",
		Description: "Summarize the environment: how many attack routes are open, how many are runtime-confirmed, " +
			"how many assets and relationships are mapped, and which sensitive assets an attacker can currently reach. " +
			"Start here to orient before enumerating anything.",
		InputSchema: obj(map[string]any{}),
		Call: func(ctx context.Context, _ map[string]any) (string, error) {
			var out json.RawMessage
			err := api.query(ctx, `{
              posture { criticalPaths activePaths suppressedPaths runtimeConfirmed kevOnPaths policyViolations nodes edges }
              riskSimulation { anyCompromiseProbability sensitivityLow sensitivityHigh
                crownJewels { name label compromiseProbability } }
            }`, &out)
			return string(out), err
		},
	}
}

func listPaths(api *API) Tool {
	return Tool{
		Name: "list_attack_paths",
		Description: "List the ranked routes from internet exposure to a sensitive asset, highest triage priority first. " +
			"`score` is the modelled end-to-end exploit probability and `priority` (0-100, banded P1/P2/P3) is the triage " +
			"order that also weighs corroboration and target sensitivity. IMPORTANT: these probabilities are expert " +
			"estimates, not measurements calibrated against real outcomes - call get_score_trust before presenting any " +
			"of them as a probability, and prefer the ranking over the absolute values.",
		InputSchema: obj(map[string]any{
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20,
				"description": "How many routes to return, priority-first."},
			"app": map[string]any{"type": "string",
				"description": "Optional application scope; omit for the whole environment."},
		}),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			var out json.RawMessage
			q := fmt.Sprintf(`{ attackPaths(%s) {
              id score priority priorityLabel priorityFactors confidenceLabel runtimeConfirmed
              scoreUpperBound correlatedHops
              nodes { name label internetExposed crownJewel } } }`, scopeArgs(args, 20))
			err := api.query(ctx, q, &out)
			return string(out), err
		},
	}
}

func explainPath(api *API) Tool {
	return Tool{
		Name: "explain_attack_path",
		Description: "Give the full kill chain for one route: every hop, the relationship type, that hop's probability, " +
			"where the probability came from (kev/epss/runtime are observed evidence; cvss/severity/heuristic are " +
			"estimates), and the MITRE ATT&CK technique. Use this before explaining or acting on a route - the hop " +
			"provenance is what tells you which parts of the story are evidence and which are assumption.",
		InputSchema: obj(map[string]any{
			"path_id": map[string]any{"type": "string", "description": "The id from list_attack_paths."},
		}, "path_id"),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			id, _ := args["path_id"].(string)
			if id == "" {
				return "", fmt.Errorf("path_id is required; get one from list_attack_paths")
			}
			var res struct {
				AttackPaths []map[string]any `json:"attackPaths"`
			}
			err := api.query(ctx, `{ attackPaths(limit: 500) {
              id score scoreUpperBound correlatedHops confidence confidenceLabel posteriorMean scoreCiLow scoreCiHigh
              mixtureScore profileScores { profile prior score }
              priority priorityLabel priorityFactors runtimeConfirmed
              nodes { id name label internetExposed crownJewel severity cvss kev }
              steps { edgeType from to probability weightBasis weightConfidence attack { id name tactic } }
              remediations { title kind rationale content } } }`, &res)
			if err != nil {
				return "", err
			}
			for _, p := range res.AttackPaths {
				if p["id"] == id {
					b, _ := json.Marshal(p)
					return string(b), nil
				}
			}
			return "", fmt.Errorf("no path %q is currently open; list_attack_paths returns the live ids", id)
		},
	}
}

func routesToTarget(api *API) Tool {
	return Tool{
		Name: "routes_to_target",
		Description: "Enumerate the k best distinct routes that reach a named sensitive asset. Answers 'how many ways in ' +" +
			"'are there, and do they share a choke point' - which single-path views hide. Cutting a hop that every route " +
			"traverses removes them all; cutting one that appears in a single route removes one.",
		InputSchema: obj(map[string]any{
			"target": map[string]any{"type": "string", "description": "Sensitive asset name, e.g. 'account-admin (effective)'."},
			"k":      map[string]any{"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
			"from":   map[string]any{"type": "string", "description": "Optional entry-point name to start from."},
		}, "target"),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			target, _ := args["target"].(string)
			if target == "" {
				return "", fmt.Errorf("target is required; get_posture lists the reachable sensitive assets")
			}
			k := intArg(args, "k", 5, 1, 20)
			from := ""
			if f, ok := args["from"].(string); ok && f != "" {
				from = fmt.Sprintf(", from: %s", jsonString(f))
			}
			var out json.RawMessage
			q := fmt.Sprintf(`{ kShortestPaths(target: %s, k: %d%s) {
              id score priority priorityLabel nodes { name label } } }`, jsonString(target), k, from)
			err := api.query(ctx, q, &out)
			return string(out), err
		},
	}
}

func listFixes(api *API) Tool {
	return Tool{
		Name: "list_fixes",
		Description: "Return the remediation plan: the fewest changes that remove the most risk, choke points first, each " +
			"with the share of critical-path risk it eliminates and how many routes it cuts. This is usually the right " +
			"answer to 'what should we do' - a hundred routes typically collapse into a handful of changes.",
		InputSchema: obj(map[string]any{
			"app": map[string]any{"type": "string", "description": "Optional application scope."},
		}),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			scope := ""
			if a, ok := args["app"].(string); ok && a != "" {
				scope = fmt.Sprintf("(app: %s)", jsonString(a))
			}
			var out json.RawMessage
			// verification is omitted on purpose: proving each fix re-runs a full
			// simulation per fix, which is minutes on a real estate. simulate_fix
			// does that for ONE change, when the agent actually wants the proof.
			err := api.query(ctx, fmt.Sprintf(`{ remediationPlan%s {
              title kind filename rationale pathCount riskCovered coveragePct } }`, scope), &out)
			return string(out), err
		},
	}
}

func simulateFix(api *API) Tool {
	return Tool{
		Name: "simulate_fix",
		Description: "Ask what actually happens if specific relationships are cut: re-runs the whole simulation with those " +
			"edges removed and reports how many routes disappear and how the compromise probability moves. This is the " +
			"tool to reach for before recommending a change - it is a deterministic counterfactual over the real graph, " +
			"not an estimate, so it settles 'would this help' instead of arguing about it.",
		InputSchema: obj(map[string]any{
			"cuts": map[string]any{
				"type": "array", "minItems": 1, "maxItems": 20,
				"description": "Relationships to remove. Use node ids from explain_attack_path steps (from/to).",
				"items": obj(map[string]any{
					"from": map[string]any{"type": "string"},
					"to":   map[string]any{"type": "string"},
				}, "from", "to"),
			},
		}, "cuts"),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			raw, ok := args["cuts"].([]any)
			if !ok || len(raw) == 0 {
				return "", fmt.Errorf("cuts is required: a list of {from, to} node ids from explain_attack_path")
			}
			var parts []string
			for _, c := range raw {
				m, ok := c.(map[string]any)
				if !ok {
					return "", fmt.Errorf("each cut must be an object with from and to")
				}
				from, _ := m["from"].(string)
				to, _ := m["to"].(string)
				if from == "" || to == "" {
					return "", fmt.Errorf("each cut needs both from and to node ids")
				}
				parts = append(parts, fmt.Sprintf("{from: %s, to: %s}", jsonString(from), jsonString(to)))
			}
			var out json.RawMessage
			q := fmt.Sprintf(`{ whatIf(cuts: [%s]) {
              removedEdges riskReduction
              beforeRisk { anyCompromiseProbability }
              afterRisk { anyCompromiseProbability }
              after { id } } }`, strings.Join(parts, ", "))
			err := api.query(ctx, q, &out)
			return string(out), err
		},
	}
}

func searchAssets(api *API) Tool {
	return Tool{
		Name:        "search_assets",
		Description: "Full-text search across indexed assets and findings by name, CVE id, or keyword. Use it to resolve a name a human mentioned into the node ids the other tools take.",
		InputSchema: obj(map[string]any{
			"query": map[string]any{"type": "string", "description": "e.g. 'log4j', 'PII', 'CVE-2021-44228'."},
			"size":  map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
		}, "query"),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			q, _ := args["query"].(string)
			if q == "" {
				return "", fmt.Errorf("query is required")
			}
			var out json.RawMessage
			err := api.query(ctx, fmt.Sprintf(`{ search(query: %s, size: %d) { id name label score } }`,
				jsonString(q), intArg(args, "size", 10, 1, 50)), &out)
			if err != nil && strings.Contains(err.Error(), "search") {
				return "", fmt.Errorf("full-text search is not enabled on this deployment (it needs OpenSearch); use list_attack_paths and get_posture instead")
			}
			return string(out), err
		},
	}
}

func scoreTrust(api *API) Tool {
	return Tool{
		Name: "get_score_trust",
		Description: "Report how well the engine's probabilities have matched reality, measured against recorded red-team " +
			"or BAS outcomes: the verdict (well-calibrated / overconfident / underconfident / insufficient-data), the " +
			"predicted-versus-observed rates, and what to do about the gap. Call this before quoting any score as a " +
			"probability. If it reports insufficient-data, the numbers are expert estimates and must be presented as " +
			"a ranking, not as odds.",
		InputSchema: obj(map[string]any{}),
		Call: func(ctx context.Context, _ map[string]any) (string, error) {
			var out json.RawMessage
			err := api.query(ctx, `{
              calibration { samples brier ece meanPredicted observedRate recommendedScale verdict hasData diagnosis }
              validation { confirmed refuted partial missed tested precision recall }
            }`, &out)
			return string(out), err
		},
	}
}

// scopeArgs renders the (app:, limit:) arguments shared by the path queries.
func scopeArgs(args map[string]any, defLimit int) string {
	parts := []string{fmt.Sprintf("limit: %d", intArg(args, "limit", defLimit, 1, 100))}
	if a, ok := args["app"].(string); ok && a != "" {
		parts = append(parts, fmt.Sprintf("app: %s", jsonString(a)))
	}
	return strings.Join(parts, ", ")
}

// intArg reads a numeric argument, clamped to the schema's bounds. JSON numbers
// arrive as float64, and a model that ignores the schema should be corrected
// rather than allowed to ask for a million rows.
func intArg(args map[string]any, key string, def, min, max int) int {
	v := def
	switch n := args[key].(type) {
	case float64:
		v = int(n)
	case int:
		v = n
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// jsonString quotes a value for inline GraphQL. Model-supplied strings reach the
// query text, so they are encoded rather than concatenated.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
