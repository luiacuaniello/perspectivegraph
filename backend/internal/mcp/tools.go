package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
		return fmt.Errorf("the engine is unreachable at %s (%w): usually temporary, so retry once - if it fails again "+
			"every other tool will fail too, and whoever runs this server has to check the engine and its address", a.BaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return statusError(resp.StatusCode)
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

// answer runs a query and returns the engine's reply as compact JSON. The engine indents
// its replies for a person reading them, and passed through as they are, a good part of
// what the model was given to read was whitespace.
func (a *API) answer(ctx context.Context, q string) (string, error) {
	var out json.RawMessage
	if err := a.query(ctx, q, &out); err != nil {
		return "", err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, out); err != nil {
		return string(out), nil
	}
	return compact.String(), nil
}

// statusError turns an HTTP status into what an agent should do about it. The number alone
// gives a model nothing to act on; whether repeating the call can help, and who can fix it
// when it cannot, is what decides its next step.
func statusError(code int) error {
	switch {
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return fmt.Errorf("the engine refused this server's credentials (HTTP %d): the API token is missing, wrong or not "+
			"allowed to read. Retrying will not help - the token is set where this server is launched (API_TOKEN or --token), "+
			"so tell the user", code)
	case code == http.StatusTooManyRequests:
		return fmt.Errorf("the engine is rate-limiting this client (HTTP %d): wait a few seconds and repeat the same call", code)
	case code >= http.StatusInternalServerError:
		return fmt.Errorf("the engine failed to answer (HTTP %d): usually temporary, so retry once and report it if it fails again", code)
	default:
		return fmt.Errorf("the engine rejected the request (HTTP %d): the same call will fail again, so change the arguments "+
			"or report it", code)
	}
}

// Tools is the curated capability set, ordered as an agent should meet them:
// orient, then enumerate, then inspect, then simulate.
func Tools(api *API) []Tool {
	return []Tool{
		readOnly(posture(api), "Posture overview"),
		readOnly(listPaths(api), "List attack paths"),
		readOnly(explainPath(api), "Explain an attack path"),
		readOnly(routesToTarget(api), "Routes to a target"),
		readOnly(listFixes(api), "List remediations"),
		readOnly(simulateFix(api), "Simulate cutting edges"),
		readOnly(searchAssets(api), "Search assets"),
		readOnly(scoreTrust(api), "Score calibration"),
	}
}

// readOnly stamps a tool with the annotations that make this surface's central property
// machine-readable: nothing here suppresses a path, opens a pull request or records a
// verdict, because an agent that can silently accept a risk is a liability rather than a
// feature.
//
// It is applied at the assembly point on purpose. Every tool passes through here, so a
// tool added later cannot quietly join the surface without a decision being made about
// it - and `TestEveryToolDeclaresItselfReadOnly` fails if one does.
//
// Idempotent: every tool is a query, including simulate_fix, which asks the engine for a
// counterfactual rather than applying one. Not open-world: they read this deployment's
// own graph, a closed and known set, not the internet.
func readOnly(t Tool, title string) Tool {
	t.Annotations = &ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		DestructiveHint: false,
		IdempotentHint:  true,
		OpenWorldHint:   false,
	}
	return t
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
			"Start here to orient before enumerating anything: it also gives the names the other tools take - the " +
			"sensitive assets routes_to_target accepts and the applications `app` arguments accept.",
		InputSchema:  obj(map[string]any{}),
		OutputSchema: postureOutput(),
		Call: func(ctx context.Context, _ map[string]any) (string, error) {
			return api.answer(ctx, `{
              posture { criticalPaths activePaths suppressedPaths runtimeConfirmed kevOnPaths policyViolations nodes edges }
              riskSimulation { anyCompromiseProbability sensitivityLow sensitivityHigh
                crownJewels { name label compromiseProbability } }
              applications
            }`)
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
			"of them as a probability, and prefer the ranking over the absolute values. It returns one page: when " +
			"`nextOffset` is not null more routes exist, and passing it as `offset` returns the next ones. Routes an " +
			"analyst has suppressed are listed too, marked `suppressed`.",
		InputSchema: obj(map[string]any{
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20,
				"description": "How many routes to return, priority-first."},
			"offset": map[string]any{"type": "integer", "minimum": 0, "default": 0,
				"description": "How many routes to skip from the top of the ranking: the `nextOffset` of the previous page. Leave it out for the first page."},
			"app": map[string]any{"type": "string", "description": appParam},
		}),
		OutputSchema: listPathsOutput(),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			limit := intArg(args, "limit", 20, 1, 100)
			offset := intArg(args, "offset", 0, 0, maxOffset)
			var res struct {
				AttackPaths []json.RawMessage `json:"attackPaths"`
			}
			// One route more than asked for: whether it comes back is how the tool knows
			// another page exists, without a second query. It is dropped before the model
			// sees it.
			q := fmt.Sprintf(`{ attackPaths(%s) {
              id score priority priorityLabel priorityReason priorityFactors confidenceLabel runtimeConfirmed suppressed
              scoreUpperBound correlatedHops
              nodes { name label internetExposed crownJewel } } }`, pageArgs(args, limit+1, offset))
			if err := api.query(ctx, q, &res); err != nil {
				return "", pagingError(err)
			}
			page := struct {
				AttackPaths []json.RawMessage `json:"attackPaths"`
				Offset      int               `json:"offset"`
				NextOffset  *int              `json:"nextOffset"`
			}{AttackPaths: res.AttackPaths, Offset: offset}
			if len(page.AttackPaths) > limit {
				page.AttackPaths = page.AttackPaths[:limit]
				next := offset + limit
				page.NextOffset = &next
			}
			if page.AttackPaths == nil {
				page.AttackPaths = []json.RawMessage{} // no routes is an empty list, not null
			}
			b, err := json.Marshal(page)
			return string(b), err
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
			"path_id": map[string]any{"type": "string", "description": "The `id` of a route from list_attack_paths. An id lasts as long as its route: one that has since been closed is reported as no longer open, and list_attack_paths gives the current ones."},
		}, "path_id"),
		OutputSchema: explainPathOutput(),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			id, _ := args["path_id"].(string)
			if id == "" {
				return "", fmt.Errorf("path_id is required; get one from list_attack_paths")
			}
			// The engine has no route-by-id query, so the ranking is read a page at a time
			// until the id turns up. The first page is nearly always the only one; the cap
			// keeps an id that does not exist from costing a walk through a huge estate.
			for page := 0; page < explainMaxPages; page++ {
				var res struct {
					AttackPaths []map[string]any `json:"attackPaths"`
				}
				err := api.query(ctx, fmt.Sprintf(`{ attackPaths(%s) {
              id score scoreUpperBound correlatedHops confidence confidenceLabel posteriorMean scoreCiLow scoreCiHigh
              mixtureScore profileScores { profile prior score }
              priority priorityLabel priorityReason priorityFactors runtimeConfirmed suppressed
              nodes { id name label internetExposed crownJewel severity cvss kev }
              steps { edgeType from to probability weightBasis weightConfidence attack { id name tactic } }
              remediations { title kind rationale content cut { from to type } } } }`, pageArgs(nil, explainPage, page*explainPage)), &res)
				if err != nil {
					if page > 0 && isNoPaging(err) {
						break // an engine too old to page: the first page was all there is to read
					}
					return "", err
				}
				for _, p := range res.AttackPaths {
					if p["id"] == id {
						b, _ := json.Marshal(p)
						return string(b), nil
					}
				}
				if len(res.AttackPaths) < explainPage {
					break
				}
			}
			return "", fmt.Errorf("no route %q is in the ranking now: its id goes when the route is closed or the "+
				"graph under it changes, and an alternate route from routes_to_target was never in it (that tool "+
				"returns the hops itself) - list_attack_paths returns the ids this tool takes", id)
		},
	}
}

func routesToTarget(api *API) Tool {
	return Tool{
		Name: "routes_to_target",
		Description: "Enumerate the k best distinct routes that reach a named sensitive asset. Answers 'how many ways in " +
			"are there, and do they share a choke point' - which single-path views hide. Cutting a hop that every route " +
			"traverses removes them all; cutting one that appears in a single route removes one. Each route comes " +
			"with its hops, ready to hand to simulate_fix. It returns the best `k` and has no further page.",
		InputSchema: obj(map[string]any{
			"target": map[string]any{"type": "string", "description": "The sensitive asset to reach, by name or node id: a `name` under get_posture's crownJewels (e.g. 'account-admin (effective)'), or an `id` from search_assets. A target nothing reaches returns an empty list, not an error."},
			"k":      map[string]any{"type": "integer", "minimum": 1, "maximum": 20, "default": 5, "description": "How many distinct routes to return, best first. Fewer routes come back when fewer exist."},
			"from":   map[string]any{"type": "string", "description": "Optional entry point to start from, by name or node id. Omit to consider every internet-exposed entry point."},
		}, "target"),
		OutputSchema: routesOutput(),
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
			// No priority: the engine computes it for the ranked routes only, and here it
			// would come back 0 on every route. The hops are asked for instead, because an
			// alternate route cannot be handed to explain_attack_path - see routesOutput.
			q := fmt.Sprintf(`{ kShortestPaths(target: %s, k: %d%s) {
              id score nodes { name label }
              steps { edgeType from to probability weightBasis } } }`, jsonString(target), k, from)
			return api.answer(ctx, q)
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
			"app": map[string]any{"type": "string", "description": appParam},
		}),
		OutputSchema: fixesOutput(),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			scope := ""
			if a, ok := args["app"].(string); ok && a != "" {
				scope = fmt.Sprintf("(app: %s)", jsonString(a))
			}
			// verification is omitted on purpose: proving each fix re-runs a full
			// simulation per fix, which is minutes on a real estate. simulate_fix
			// does that for ONE change, when the agent actually wants the proof.
			return api.answer(ctx, fmt.Sprintf(`{ remediationPlan%s {
              title kind filename rationale pathCount riskCovered coveragePct } }`, scope))
		},
	}
}

func simulateFix(api *API) Tool {
	return Tool{
		Name: "simulate_fix",
		Description: "Ask what actually happens if specific relationships are cut: re-runs the whole simulation with those " +
			"edges removed and reports how many routes disappear and how the compromise probability moves. This is the " +
			"tool to reach for before recommending a change - it is a deterministic counterfactual over the real graph, " +
			"not an estimate, so it settles 'would this help' instead of arguing about it. It changes nothing: the " +
			"graph, the environment and every recorded decision stay as they are, so it needs no confirmation and can " +
			"be repeated freely.",
		InputSchema: obj(map[string]any{
			"cuts": map[string]any{
				"type": "array", "minItems": 1, "maxItems": 20,
				"description": "Relationships to remove. Take each from a step of explain_attack_path (its from/to), or pass the `cut` of one of that route's remediations as it is.",
				"items": obj(map[string]any{
					"from": map[string]any{"type": "string", "description": "Where the relationship starts: the `from` of a step in explain_attack_path (a node id or name)."},
					"to":   map[string]any{"type": "string", "description": "Where the relationship ends: the `to` of the same step (a node id or name)."},
					"type": map[string]any{"type": "string", "description": "Optional relationship type to cut: the step's `edgeType`, e.g. EXPOSES or HAS_PERMISSION. Omit to cut every relationship from `from` to `to`."},
				}, "from", "to"),
			},
		}, "cuts"),
		OutputSchema: simulateOutput(),
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
				cut := fmt.Sprintf("from: %s, to: %s", jsonString(from), jsonString(to))
				// The type was accepted and dropped before, so a cut copied from a
				// remediation - which names one - removed every relationship between the
				// two nodes and answered a broader question than the one asked.
				if typ, _ := m["type"].(string); typ != "" {
					cut += ", type: " + jsonString(typ)
				}
				parts = append(parts, "{"+cut+"}")
			}
			q := fmt.Sprintf(`{ whatIf(cuts: [%s]) {
              removedEdges riskReduction
              beforeRisk { anyCompromiseProbability }
              afterRisk { anyCompromiseProbability }
              after { id } } }`, strings.Join(parts, ", "))
			return api.answer(ctx, q)
		},
	}
}

// ErrSearchDisabled is what search_assets answers on a deployment without OpenSearch.
//
// It is decided by asking the engine, not by reading error text. With OpenSearch off the
// engine does not fail at all - its indexer answers "no hits" - so the old check (any
// error mentioning "search") never fired in the case it was written for, and an agent
// read an empty result as "no asset by that name exists". It fired instead on real
// OpenSearch failures, whose message carries the `_search` URL, and called an outage a
// missing feature.
var ErrSearchDisabled = errors.New("full-text search is not enabled on this deployment (it needs OpenSearch); use list_attack_paths and get_posture instead")

func searchAssets(api *API) Tool {
	return Tool{
		Name: "search_assets",
		Description: "Full-text search across indexed assets and findings by name, CVE id, or keyword. Use it to resolve a " +
			"name a human mentioned into the node ids the other tools take. It needs OpenSearch on the deployment: where " +
			"that is off it answers with an error saying so, never with an empty list, and get_posture and " +
			"list_attack_paths are then where names come from. It returns the best `size` matches and has no further " +
			"page: narrow the query instead.",
		InputSchema: obj(map[string]any{
			"query": map[string]any{"type": "string", "description": "Text matched against asset and finding names, labels, ids, severities and CWEs, e.g. 'log4j', 'PII', 'CVE-2021-44228'."},
			"size":  map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 10, "description": "Maximum number of matches to return, best match first."},
		}, "query"),
		OutputSchema: searchOutput(),
		Call: func(ctx context.Context, args map[string]any) (string, error) {
			q, _ := args["query"].(string)
			if q == "" {
				return "", fmt.Errorf("query is required")
			}
			// searchEnabled rides in the same request: the dashboard uses it for exactly this,
			// telling "feature off" apart from "no matches".
			var out struct {
				SearchEnabled bool            `json:"searchEnabled"`
				Search        json.RawMessage `json:"search"`
			}
			if err := api.query(ctx, fmt.Sprintf(`{ searchEnabled search(query: %s, size: %d) { id name label score } }`,
				jsonString(q), intArg(args, "size", 10, 1, 50)), &out); err != nil {
				return "", err
			}
			if !out.SearchEnabled {
				return "", ErrSearchDisabled
			}
			hits := out.Search
			if len(hits) == 0 || string(hits) == "null" {
				hits = json.RawMessage("[]")
			}
			b, err := json.Marshal(map[string]json.RawMessage{"search": hits})
			return string(b), err
		},
	}
}

func scoreTrust(api *API) Tool {
	return Tool{
		Name: "get_score_trust",
		Description: "Report how well the engine's probabilities have matched reality, measured against recorded red-team " +
			"or BAS outcomes: the verdict (well-calibrated / calibrated-on-average / overconfident / underconfident / " +
			"insufficient-data; calibrated-on-average means only the average matches, so no individual score may be " +
			"quoted as a probability), the " +
			"predicted-versus-observed rates, and what to do about the gap. Call this before quoting any score as a " +
			"probability. If it reports insufficient-data, the numbers are expert estimates and must be presented as " +
			"the model's own estimate, not as odds. It also reports discrimination - whether the score, and separately " +
			"the triage Priority order, put confirmed paths above refuted ones (AUC with a 95% interval). Do not " +
			"present the ranking as evidence of which path is most dangerous unless priorityDiscrimination reads " +
			"'discriminates'; 'insufficient-data' or 'indistinguishable-from-chance' means the order has not been " +
			"shown to beat a coin, and must be said so.",
		InputSchema:  obj(map[string]any{}),
		OutputSchema: scoreTrustOutput(),
		Call: func(ctx context.Context, _ map[string]any) (string, error) {
			return api.answer(ctx, `{
              calibration { samples brier ece meanPredicted observedRate recommendedScale verdict hasData diagnosis
                discrimination { auc aucLow aucHigh verdict positives negatives hasData }
                priorityDiscrimination { auc aucLow aucHigh verdict positives negatives hasData } }
              validation { confirmed refuted partial missed tested precision recall }
            }`)
		},
	}
}

// appParam describes the `app` argument wherever it appears. An agent cannot guess what an
// "application" is called here, so it is told where the names are listed.
const appParam = "Restrict to one application, by a name from get_posture's `applications`: a repository slug or the " +
	"value of a cloud resource's `app` tag, e.g. 'payments-api'. The match is exact, and a name the environment does " +
	"not know returns nothing. Omit for the whole environment."

const (
	// maxOffset bounds how far a model can ask to skip; the engine answers a page past the
	// end with an empty list.
	maxOffset = 1_000_000
	// explain_attack_path reads the ranking this many routes at a time, for at most this
	// many pages.
	explainPage     = 500
	explainMaxPages = 20
)

// pageArgs renders the (limit:, offset:, app:) arguments of a route query. offset is sent
// only past the first page: an engine older than paging rejects the argument, and the
// first page is the one that has to keep working against it.
func pageArgs(args map[string]any, limit, offset int) string {
	parts := []string{fmt.Sprintf("limit: %d", limit)}
	if offset > 0 {
		parts = append(parts, fmt.Sprintf("offset: %d", offset))
	}
	if a, ok := args["app"].(string); ok && a != "" {
		parts = append(parts, fmt.Sprintf("app: %s", jsonString(a)))
	}
	return strings.Join(parts, ", ")
}

// isNoPaging recognises an engine that predates the offset argument.
func isNoPaging(err error) bool {
	return err != nil && strings.Contains(err.Error(), `Unknown argument "offset"`)
}

// pagingError says what an agent can do when it asks such an engine for a later page:
// the raw rejection would read as a bug in the tool.
func pagingError(err error) error {
	if isNoPaging(err) {
		return errors.New("this engine is too old to page through routes, so only the first page can be listed: narrow it " +
			"with `app`, or use routes_to_target for one asset - upgrading the engine lifts the limit")
	}
	return err
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
