// Package api is the Backend-For-Frontend. It exposes a GraphQL schema so the
// dashboard can ask for exactly the slice of the graph it needs (attack paths,
// posture summary, policy violations, full-text search, or the raw node/edge
// view for Cytoscape).
package api

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/luiacuaniello/perspectivegraph/internal/action"
	"github.com/luiacuaniello/perspectivegraph/internal/ai"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/attck"
	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/detection"
	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/policy"
	"github.com/luiacuaniello/perspectivegraph/internal/ratelimit"
	"github.com/luiacuaniello/perspectivegraph/internal/remediation"
	"github.com/luiacuaniello/perspectivegraph/internal/search"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// API wires the data sources the resolvers read from. Queries are scoped to the
// caller's tenant (from the authenticated principal; the default tenant when
// auth is open).
type API struct {
	manager      *graph.Manager
	analyzer     *analyzer.Service
	search       search.Indexer
	authn        auth.Authenticator
	audit        audit.Recorder
	limiter      *ratelimit.Limiter
	suppress     *suppress.Store
	history      *history.Store
	ticket       *ticket.Store
	validation   *validation.Store
	corsOrigins  []string
	exportSigner *exportsign.Signer
	exfil        *secwatch.Watcher // exfiltration detector (attack-map bulk reads)
	authGuard    *secwatch.Watcher // auth brute-force lockout
	authInfo     AuthInfo          // public auth config for the SPA login gate
	prOpener     action.PROpener   // opens remediation pull requests (nil → disabled)
	ai           ai.Client         // AI-native layer (nil/Nop → disabled)
}

func New(manager *graph.Manager, svc *analyzer.Service, idx search.Indexer) *API {
	if idx == nil {
		idx = search.Noop{}
	}
	// Default to an in-memory suppression store so triage works out of the box;
	// WithSuppress swaps in a file-backed one when SUPPRESSIONS_PATH is set.
	mem, _ := suppress.New("")
	hist, _ := history.New("")
	tk, _ := ticket.New("", "")
	val, _ := validation.New("")
	return &API{
		manager: manager, analyzer: svc, search: idx, audit: audit.Nop{},
		suppress: mem, history: hist, ticket: tk, validation: val,
		// Sensible default so the dev/demo dashboards work; overridden by
		// WithCORSOrigins from CORS_ALLOWED_ORIGINS.
		corsOrigins: []string{"http://localhost:5173", "http://localhost:3000"},
	}
}

// WithValidation attaches the red-team/BAS validation store the API reads for
// per-path verdicts and the precision/recall metric. A nil store keeps the
// default in-memory one. Returns the API for chaining.
func (a *API) WithValidation(v *validation.Store) *API {
	if v != nil {
		a.validation = v
	}
	return a
}

// WithTickets attaches the remediation ticketing store (file-backed and/or
// webhook-dispatching). A nil store leaves the default in-memory one in place.
// Returns the API for chaining.
func (a *API) WithTickets(t *ticket.Store) *API {
	if t != nil {
		a.ticket = t
	}
	return a
}

// WithSuppress attaches the (file-backed) triage/suppression store. A nil store
// leaves the default in-memory one in place. Returns the API for chaining.
func (a *API) WithSuppress(s *suppress.Store) *API {
	if s != nil {
		a.suppress = s
	}
	return a
}

// WithHistory attaches the temporal store the API reads for path age, MTTR and
// the posture trend. A nil store leaves the default in-memory one in place.
// Returns the API for chaining.
func (a *API) WithHistory(h *history.Store) *API {
	if h != nil {
		a.history = h
	}
	return a
}

// WithAuth requires a bearer credential (≥ viewer) on the GraphQL endpoint,
// audits access, and disables the in-browser GraphiQL playground. Returns the
// API for chaining.
func (a *API) WithAuth(authn auth.Authenticator, rec audit.Recorder) *API {
	a.authn = authn
	if rec != nil {
		a.audit = rec
	}
	return a
}

func (a *API) authEnabled() bool { return a.authn != nil && a.authn.Enabled() }

// tenant returns the caller's tenant from the request context.
func tenantOf(ctx context.Context) string {
	return auth.PrincipalFromContext(ctx).Tenant
}

// auditView records a *read* of the sensitive "attack map" - the ranked paths,
// the raw graph, or an export - to the tamper-evident audit log, so a deployment
// can answer "who viewed (or exfiltrated) which attack paths". The tool itself is
// a map of how to breach the org, so its reads are governed, not just its writes.
// A no-op unless AUDIT_LOG_PATH is configured (a.audit is then audit.Nop).
func (a *API) auditView(ctx context.Context, action string, fields map[string]any) {
	p := auth.PrincipalFromContext(ctx)
	a.audit.Record(action, p.Subject, p.Role.String(), p.Tenant, fields)
	// Exfiltration watch: a principal pulling an unusual volume of attack paths
	// (bulk reads/exports) in a short window is the tool's own data walking out the
	// door - fire one alert per principal per cooldown.
	if a.exfil.Enabled() {
		if n := viewCount(fields); n > 0 {
			a.exfil.Observe(p.Subject+"@"+p.Tenant, n)
		}
	}
}

// viewCount sums the "size" of a view from the audit fields, so one OSCAL export
// of 200 paths weighs 200 against the exfil threshold (not 1).
func viewCount(f map[string]any) int {
	n := 0
	for _, k := range []string{"paths", "assets", "count"} {
		if v, ok := f[k].(int); ok {
			n += v
		}
	}
	return n
}

// pathIDsCapped returns up to limit path ids for an audit record, so a large
// result set can't bloat the log while still naming what was seen.
func pathIDsCapped(paths []analyzer.AttackPath, limit int) []string {
	if len(paths) > limit {
		paths = paths[:limit]
	}
	ids := make([]string, 0, len(paths))
	for _, p := range paths {
		ids = append(ids, p.ID)
	}
	return ids
}

// historyView is the resolved shape of the `history` query: the posture trend
// plus the rolled-up temporal stats and whether the store is persistent.
type historyView struct {
	Trend      []history.PosturePoint
	Stats      history.Stats
	Persistent bool
}

func (a *API) Schema() (graphql.Schema, error) {
	nodeType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Node",
		Fields: graphql.Fields{
			"id":                   &graphql.Field{Type: graphql.NewNonNull(graphql.String), Resolve: field[ontology.Node](func(n ontology.Node) any { return n.ID })},
			"label":                &graphql.Field{Type: graphql.String, Resolve: field[ontology.Node](func(n ontology.Node) any { return string(n.Label) })},
			"name":                 &graphql.Field{Type: graphql.String, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Name })},
			"internetExposed":      &graphql.Field{Type: graphql.Boolean, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropInternetExposed) })},
			"crownJewel":           &graphql.Field{Type: graphql.Boolean, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropCrownJewel) })},
			"crownJewelBasis":      &graphql.Field{Type: graphql.String, Description: "Why this node is a crown jewel: \"tagged\" (explicit), \"classified:<source>:<kind>\" (a real classifier - Macie/DLP), or \"inferred:<signal>\" (guessed from a sensitive-data signal).", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropCrownJewelBasis] })},
			"classification":       &graphql.Field{Type: graphql.String, Description: "Data classification from a real classifier (Macie/DLP/tag policy): pii|phi|pci|financial|secret|…", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropClassification] })},
			"secretsScrubbed":      &graphql.Field{Type: graphql.Boolean, Description: "True when a secret-looking value (token, key, password) was redacted out of this node's properties at ingest. The finding is kept; the credential is not - so the attack map never hands out a live secret.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropSecretsScrubbed) })},
			"runtimeAlert":         &graphql.Field{Type: graphql.Boolean, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropRuntimeAlert) })},
			"severity":             &graphql.Field{Type: graphql.String, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropSeverity] })},
			"cvss":                 &graphql.Field{Type: graphql.Float, Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropCVSS] })},
			"kev":                  &graphql.Field{Type: graphql.Boolean, Description: "In CISA's Known Exploited Vulnerabilities catalog (exploited in the wild).", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Bool(ontology.PropKEV) })},
			"epss":                 &graphql.Field{Type: graphql.Float, Description: "FIRST EPSS probability of exploitation within 30 days, [0,1].", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropEPSS] })},
			"resolutionMethod":     &graphql.Field{Type: graphql.String, Description: "How this node's identity was inferred by the resolver (digest|tag|name). Absent when the identity was asserted by a tool, not inferred.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropResolutionMethod] })},
			"resolutionConfidence": &graphql.Field{Type: graphql.Float, Description: "How confident the inferred identity/join is, [0,1]. <1 means a heuristic correlation an analyst should verify.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropResolutionConfidence] })},
			"resolutionAlias":      &graphql.Field{Type: graphql.String, Description: "The raw reference that was matched to produce this inferred identity.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropResolutionAlias] })},
			"signed":               &graphql.Field{Type: graphql.Boolean, Description: "Supply-chain: image signature verified (cosign). Null when never assessed - distinct from false (verified unsigned).", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropSigned] })},
			"slsaLevel":            &graphql.Field{Type: graphql.Int, Description: "Supply-chain: SLSA build-provenance level [0..4]; higher is a more trustworthy build.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropSLSALevel] })},
			"sbomComponents":       &graphql.Field{Type: graphql.Int, Description: "Supply-chain: number of SBOM components recorded for this image.", Resolve: field[ontology.Node](func(n ontology.Node) any { return n.Properties[ontology.PropSBOMComponents] })},
		},
	})

	// MITRE ATT&CK technique a hop maps to (a documented best-fit heuristic).
	attackType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "AttackTechnique",
		Description: "The MITRE ATT&CK technique this hop corresponds to (heuristic mapping from the edge type, not an observation).",
		Fields: graphql.Fields{
			"id":       &graphql.Field{Type: graphql.String, Description: "Technique ID, e.g. T1190 or T1078.004.", Resolve: field[attck.Technique](func(t attck.Technique) any { return t.ID })},
			"name":     &graphql.Field{Type: graphql.String, Resolve: field[attck.Technique](func(t attck.Technique) any { return t.Name })},
			"tactic":   &graphql.Field{Type: graphql.String, Resolve: field[attck.Technique](func(t attck.Technique) any { return t.Tactic })},
			"tacticId": &graphql.Field{Type: graphql.String, Resolve: field[attck.Technique](func(t attck.Technique) any { return t.TacticID })},
			"url":      &graphql.Field{Type: graphql.String, Description: "Canonical MITRE ATT&CK page.", Resolve: field[attck.Technique](func(t attck.Technique) any { return t.URL() })},
		},
	})

	edgeType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Edge",
		Fields: graphql.Fields{
			"type":        &graphql.Field{Type: graphql.String, Resolve: field[ontology.Edge](func(e ontology.Edge) any { return string(e.Type) })},
			"from":        &graphql.Field{Type: graphql.String, Resolve: field[ontology.Edge](func(e ontology.Edge) any { return e.From })},
			"to":          &graphql.Field{Type: graphql.String, Resolve: field[ontology.Edge](func(e ontology.Edge) any { return e.To })},
			"probability": &graphql.Field{Type: graphql.Float, Resolve: field[ontology.Edge](func(e ontology.Edge) any { return e.ExploitProbability })},
			"attack": &graphql.Field{Type: attackType, Resolve: field[ontology.Edge](func(e ontology.Edge) any {
				if t, ok := attck.ForEdge(e.Type); ok {
					return t
				}
				return nil
			})},
		},
	})

	stepType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AttackPathStep",
		Fields: graphql.Fields{
			"edgeType":    &graphql.Field{Type: graphql.String, Resolve: field[analyzer.Step](func(s analyzer.Step) any { return string(s.EdgeType) })},
			"from":        &graphql.Field{Type: graphql.String, Resolve: field[analyzer.Step](func(s analyzer.Step) any { return s.From })},
			"to":          &graphql.Field{Type: graphql.String, Resolve: field[analyzer.Step](func(s analyzer.Step) any { return s.To })},
			"probability": &graphql.Field{Type: graphql.Float, Resolve: field[analyzer.Step](func(s analyzer.Step) any { return s.Probability })},
			"attack": &graphql.Field{Type: attackType, Description: "The MITRE ATT&CK technique this hop maps to (nil for structural hops).", Resolve: field[analyzer.Step](func(s analyzer.Step) any {
				if t, ok := attck.ForEdge(s.EdgeType); ok {
					return t
				}
				return nil
			})},
			"resolutionMethod": &graphql.Field{Type: graphql.String, Description: "Set when this hop's join was inferred by the resolver (digest|tag|name); absent for a hard, tool-asserted edge.", Resolve: field[analyzer.Step](func(s analyzer.Step) any {
				if s.ResolutionMethod == "" {
					return nil
				}
				return s.ResolutionMethod
			})},
			"resolutionConfidence": &graphql.Field{Type: graphql.Float, Description: "How confident this inferred hop is, [0,1]. <1 means a heuristic correlation to verify (and the probability is already discounted for it).", Resolve: field[analyzer.Step](func(s analyzer.Step) any {
				if s.ResolutionMethod == "" {
					return nil
				}
				return s.ResolutionConfidence
			})},
			"weightBasis":      &graphql.Field{Type: graphql.String, Description: "Where this hop's probability came from: kev|epss|runtime (evidence) vs cvss|severity|heuristic (estimate).", Resolve: field[analyzer.Step](func(s analyzer.Step) any { return s.WeightBasis })},
			"weightConfidence": &graphql.Field{Type: graphql.Float, Description: "How much to trust this hop's probability, [0,1], given its basis.", Resolve: field[analyzer.Step](func(s analyzer.Step) any { return s.WeightConfidence })},
		},
	})

	remediationEffectType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "RemediationEffect",
		Description: "Closed-loop verification of a remediation: the result of simulating its removal (what-if) over the current graph - proof the fix cuts the path, not just a generated scaffold.",
		Fields: graphql.Fields{
			"removedEdges":     &graphql.Field{Type: graphql.Int, Description: "Graph edges the fix actually severs."},
			"pathsBefore":      &graphql.Field{Type: graphql.Int},
			"pathsAfter":       &graphql.Field{Type: graphql.Int},
			"pathsEliminated":  &graphql.Field{Type: graphql.Int, Description: "Critical paths removed by applying this fix."},
			"riskReductionPct": &graphql.Field{Type: graphql.Float, Description: "Drop in P(any crown jewel compromised), in percentage points."},
			"verified":         &graphql.Field{Type: graphql.Boolean, Description: "True when simulating the fix removes the edge and measurably reduces paths/risk."},
		},
	})

	suggestionType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Remediation",
		Fields: graphql.Fields{
			"title":     &graphql.Field{Type: graphql.String, Resolve: field[remediation.Suggestion](func(s remediation.Suggestion) any { return s.Title })},
			"kind":      &graphql.Field{Type: graphql.String, Resolve: field[remediation.Suggestion](func(s remediation.Suggestion) any { return s.Kind })},
			"filename":  &graphql.Field{Type: graphql.String, Resolve: field[remediation.Suggestion](func(s remediation.Suggestion) any { return s.Filename })},
			"content":   &graphql.Field{Type: graphql.String, Resolve: field[remediation.Suggestion](func(s remediation.Suggestion) any { return s.Content })},
			"rationale": &graphql.Field{Type: graphql.String, Resolve: field[remediation.Suggestion](func(s remediation.Suggestion) any { return s.Rationale })},
			"verification": &graphql.Field{
				Type:        remediationEffectType,
				Description: "Simulated effect of applying this fix - the closed-loop proof it cuts the path.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return a.verifyCut(p.Context, p.Source.(remediation.Suggestion).Cut)
				},
			},
		},
	})

	detectionType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "Detection",
		Description: "Generated detection-as-code (Falco / Sigma) that catches exploitation of this path.",
		Fields: graphql.Fields{
			"kind":      &graphql.Field{Type: graphql.String, Resolve: field[detection.Detection](func(d detection.Detection) any { return d.Kind })},
			"title":     &graphql.Field{Type: graphql.String, Resolve: field[detection.Detection](func(d detection.Detection) any { return d.Title })},
			"filename":  &graphql.Field{Type: graphql.String, Resolve: field[detection.Detection](func(d detection.Detection) any { return d.Filename })},
			"content":   &graphql.Field{Type: graphql.String, Resolve: field[detection.Detection](func(d detection.Detection) any { return d.Content })},
			"rationale": &graphql.Field{Type: graphql.String, Resolve: field[detection.Detection](func(d detection.Detection) any { return d.Rationale })},
		},
	})

	fixType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "Fix",
		Description: "One remediation in the optimizer's plan, with the share of critical-path risk it removes.",
		Fields: graphql.Fields{
			"title":       &graphql.Field{Type: graphql.String, Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.Suggestion.Title })},
			"kind":        &graphql.Field{Type: graphql.String, Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.Suggestion.Kind })},
			"filename":    &graphql.Field{Type: graphql.String, Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.Suggestion.Filename })},
			"content":     &graphql.Field{Type: graphql.String, Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.Suggestion.Content })},
			"rationale":   &graphql.Field{Type: graphql.String, Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.Suggestion.Rationale })},
			"pathsCut":    &graphql.Field{Type: graphql.NewList(graphql.String), Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.PathsCut })},
			"pathCount":   &graphql.Field{Type: graphql.Int, Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.PathCount })},
			"riskCovered": &graphql.Field{Type: graphql.Float, Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.RiskCovered })},
			"coveragePct": &graphql.Field{Type: graphql.Float, Resolve: field[remediation.Fix](func(f remediation.Fix) any { return f.CoveragePct })},
			"verification": &graphql.Field{
				Type:        remediationEffectType,
				Description: "Independently simulated effect of this fix (what-if) - verifies it removes the credited paths, not just claims to.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return a.verifyCut(p.Context, p.Source.(remediation.Fix).Suggestion.Cut)
				},
			},
		},
	})

	suppressionType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "Suppression",
		Description: "An analyst's triage decision to take this path off the active board (accept-risk | false-positive | mitigating-control | duplicate), with an accountable owner and optional expiry.",
		Fields: graphql.Fields{
			"reason":    &graphql.Field{Type: graphql.String, Resolve: field[suppress.Record](func(r suppress.Record) any { return string(r.Reason) })},
			"owner":     &graphql.Field{Type: graphql.String, Resolve: field[suppress.Record](func(r suppress.Record) any { return r.Owner })},
			"note":      &graphql.Field{Type: graphql.String, Resolve: field[suppress.Record](func(r suppress.Record) any { return r.Note })},
			"createdAt": &graphql.Field{Type: graphql.String, Resolve: field[suppress.Record](func(r suppress.Record) any { return r.CreatedAt.UTC().Format(time.RFC3339) })},
			"expiresAt": &graphql.Field{Type: graphql.String, Resolve: field[suppress.Record](func(r suppress.Record) any {
				if r.ExpiresAt == nil {
					return nil
				}
				return r.ExpiresAt.UTC().Format(time.RFC3339)
			})},
		},
	})

	ticketType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "Ticket",
		Description: "An owned, tracked unit of remediation work for this path - the closed-loop accountability a generated fix lacks.",
		Fields: graphql.Fields{
			"id":          &graphql.Field{Type: graphql.String, Resolve: field[ticket.Ticket](func(t ticket.Ticket) any { return t.ID })},
			"owner":       &graphql.Field{Type: graphql.String, Resolve: field[ticket.Ticket](func(t ticket.Ticket) any { return t.Owner })},
			"title":       &graphql.Field{Type: graphql.String, Resolve: field[ticket.Ticket](func(t ticket.Ticket) any { return t.Title })},
			"status":      &graphql.Field{Type: graphql.String, Resolve: field[ticket.Ticket](func(t ticket.Ticket) any { return string(t.Status) })},
			"externalUrl": &graphql.Field{Type: graphql.String, Resolve: field[ticket.Ticket](func(t ticket.Ticket) any { return t.ExternalURL })},
			"createdAt":   &graphql.Field{Type: graphql.String, Resolve: field[ticket.Ticket](func(t ticket.Ticket) any { return t.CreatedAt.UTC().Format(time.RFC3339) })},
		},
	})

	validationType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "Validation",
		Description: "A red-team/BAS verdict on whether this path is real: confirmed | refuted | partial - the evidence that turns a modeled path into a tested one.",
		Fields: graphql.Fields{
			"outcome":  &graphql.Field{Type: graphql.String, Resolve: field[validation.Record](func(r validation.Record) any { return string(r.Outcome) })},
			"source":   &graphql.Field{Type: graphql.String, Description: "The BAS tool or tester that produced the verdict.", Resolve: field[validation.Record](func(r validation.Record) any { return r.Source })},
			"evidence": &graphql.Field{Type: graphql.String, Resolve: field[validation.Record](func(r validation.Record) any { return r.Evidence })},
			"testedAt": &graphql.Field{Type: graphql.String, Resolve: field[validation.Record](func(r validation.Record) any { return r.TestedAt.UTC().Format(time.RFC3339) })},
		},
	})

	pathType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AttackPath",
		Fields: graphql.Fields{
			"id":               &graphql.Field{Type: graphql.String, Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ID })},
			"score":            &graphql.Field{Type: graphql.Float, Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Score })},
			"runtimeConfirmed": &graphql.Field{Type: graphql.Boolean, Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.RuntimeConfirmed })},
			"confidence":       &graphql.Field{Type: graphql.Float, Description: "How much to trust this path's score given how its edge weights were derived (mean hop weight-confidence, [0,1]).", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Confidence })},
			"confidenceLabel":  &graphql.Field{Type: graphql.String, Description: "Qualitative band for the score's trustworthiness: high|medium|low - an honest answer to \"why this %?\" instead of false precision.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ConfidenceLabel })},
			"scoreUpperBound":  &graphql.Field{Type: graphql.Float, Description: "The path score if its hops share a common cause rather than being independent: the weakest hop's probability (the comonotonic upper bound). The headline score multiplies hops as if independent - a lower bound under positive correlation - so the true exploitability lies in [score, scoreUpperBound]. A wide gap means the independence assumption matters.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ScoreUpperBound })},
			"correlatedHops":   &graphql.Field{Type: graphql.Boolean, Description: "True when two or more hops rest on the same weight basis - a concrete reason the hops may not be independent, so the score/scoreUpperBound band is grounded rather than theoretical. Does not change the score.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.CorrelatedHops })},
			"priority":         &graphql.Field{Type: graphql.Float, Description: "Composite triage priority [0,100] blending exploitability (score) and trust (confidence) with corroboration (runtime-confirmed, KEV on path), target sensitivity (classified > tagged > inferred jewel), and entry blast radius. Paths are returned priority-first, so attackPaths(limit:N) is the actionable Top-N.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Priority })},
			"priorityLabel":    &graphql.Field{Type: graphql.String, Description: "Priority band: P1 (≥70) | P2 (≥40) | P3 - the \"fix these first\" bucket.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.PriorityLabel })},
			"priorityFactors":  &graphql.Field{Type: graphql.NewList(graphql.String), Description: "Human-readable reasons behind the priority (e.g. \"runtime-confirmed (active)\", \"KEV on path\", \"classified PII target\", \"entry shared by N paths\") - explainable triage, not a black-box rank.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.PriorityFactors })},
			"nodes":            &graphql.Field{Type: graphql.NewList(nodeType), Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Nodes })},
			"steps":            &graphql.Field{Type: graphql.NewList(stepType), Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Steps })},
			"suppressed": &graphql.Field{
				Type:        graphql.Boolean,
				Description: "True when an in-force triage decision hides this path from the active board.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					ap := p.Source.(analyzer.AttackPath)
					_, ok := a.suppress.Get(tenantOf(p.Context), ap.ID)
					return ok, nil
				},
			},
			"suppression": &graphql.Field{
				Type:        suppressionType,
				Description: "The triage decision in force for this path, if any.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					ap := p.Source.(analyzer.AttackPath)
					if rec, ok := a.suppress.Get(tenantOf(p.Context), ap.ID); ok {
						return rec, nil
					}
					return nil, nil
				},
			},
			"firstSeen": &graphql.Field{
				Type:        graphql.String,
				Description: "When this path was first observed (RFC3339). Null until history has recorded a pass.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rec, ok := a.history.Get(tenantOf(p.Context), p.Source.(analyzer.AttackPath).ID); ok {
						return rec.FirstSeen.UTC().Format(time.RFC3339), nil
					}
					return nil, nil
				},
			},
			"openForSeconds": &graphql.Field{
				Type:        graphql.Int,
				Description: "How long this path has been continuously open, in seconds (since first_seen of the current occurrence).",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rec, ok := a.history.Get(tenantOf(p.Context), p.Source.(analyzer.AttackPath).ID); ok {
						return int(time.Since(rec.FirstSeen).Seconds()), nil
					}
					return nil, nil
				},
			},
			"reopens": &graphql.Field{
				Type:        graphql.Int,
				Description: "How many times this path resolved and then came back - a flapping/regression signal.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rec, ok := a.history.Get(tenantOf(p.Context), p.Source.(analyzer.AttackPath).ID); ok {
						return rec.Reopens, nil
					}
					return 0, nil
				},
			},
			"ticket": &graphql.Field{
				Type:        ticketType,
				Description: "The open remediation ticket for this path, if one has been raised.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if tk, ok := a.ticket.OpenForPath(tenantOf(p.Context), p.Source.(analyzer.AttackPath).ID); ok {
						return tk, nil
					}
					return nil, nil
				},
			},
			"validation": &graphql.Field{
				Type:        validationType,
				Description: "The latest red-team/BAS verdict on whether this path is real, if it has been tested.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if v, ok := a.validation.Get(tenantOf(p.Context), p.Source.(analyzer.AttackPath).ID); ok {
						return v, nil
					}
					return nil, nil
				},
			},
			"remediations": &graphql.Field{
				Type:        graphql.NewList(suggestionType),
				Description: "Generated artifacts (K8s NetworkPolicy / Terraform) that cut an edge of this path.",
				Resolve:     field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return remediation.Generate(p) }),
			},
			"detections": &graphql.Field{
				Type:        graphql.NewList(detectionType),
				Description: "Generated Falco/Sigma rules that detect exploitation of this path.",
				Resolve:     field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return detection.Generate(p) }),
			},
		},
	})

	violationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "PolicyViolation",
		Fields: graphql.Fields{
			"invariantId": &graphql.Field{Type: graphql.String, Resolve: field[policy.Violation](func(v policy.Violation) any { return v.InvariantID })},
			"description": &graphql.Field{Type: graphql.String, Resolve: field[policy.Violation](func(v policy.Violation) any { return v.Description })},
			"severity":    &graphql.Field{Type: graphql.String, Resolve: field[policy.Violation](func(v policy.Violation) any { return v.Severity })},
			"nodes":       &graphql.Field{Type: graphql.NewList(nodeType), Resolve: field[policy.Violation](func(v policy.Violation) any { return v.Nodes })},
		},
	})

	hitType := graphql.NewObject(graphql.ObjectConfig{
		Name: "SearchHit",
		Fields: graphql.Fields{
			"id":    &graphql.Field{Type: graphql.String, Resolve: field[search.Hit](func(h search.Hit) any { return h.ID })},
			"label": &graphql.Field{Type: graphql.String, Resolve: field[search.Hit](func(h search.Hit) any { return h.Label })},
			"name":  &graphql.Field{Type: graphql.String, Resolve: field[search.Hit](func(h search.Hit) any { return h.Name })},
			"score": &graphql.Field{Type: graphql.Float, Resolve: field[search.Hit](func(h search.Hit) any { return h.Score })},
		},
	})

	graphViewType := graphql.NewObject(graphql.ObjectConfig{
		Name: "GraphView",
		Fields: graphql.Fields{
			"nodes": &graphql.Field{Type: graphql.NewList(nodeType)},
			"edges": &graphql.Field{Type: graphql.NewList(edgeType)},
		},
	})

	postureType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Posture",
		Fields: graphql.Fields{
			"criticalPaths":    &graphql.Field{Type: graphql.Int, Description: "All critical paths found this pass (active + suppressed)."},
			"activePaths":      &graphql.Field{Type: graphql.Int, Description: "Critical paths on the active board (not suppressed)."},
			"suppressedPaths":  &graphql.Field{Type: graphql.Int, Description: "Critical paths an analyst has triaged off the board (accept-risk / false-positive / …)."},
			"runtimeConfirmed": &graphql.Field{Type: graphql.Int},
			"kevOnPaths":       &graphql.Field{Type: graphql.Int, Description: "Distinct KEV-listed CVEs sitting on a critical attack path."},
			"policyViolations": &graphql.Field{Type: graphql.Int},
			"nodes":            &graphql.Field{Type: graphql.Int},
			"edges":            &graphql.Field{Type: graphql.Int},
		},
	})

	crownJewelRiskType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "CrownJewelRisk",
		Description: "A crown jewel's Monte Carlo compromise probability with a 95% Wilson CI.",
		Fields: graphql.Fields{
			"id":                    &graphql.Field{Type: graphql.String, Resolve: field[analyzer.CrownJewelRisk](func(c analyzer.CrownJewelRisk) any { return c.ID })},
			"name":                  &graphql.Field{Type: graphql.String, Resolve: field[analyzer.CrownJewelRisk](func(c analyzer.CrownJewelRisk) any { return c.Name })},
			"label":                 &graphql.Field{Type: graphql.String, Resolve: field[analyzer.CrownJewelRisk](func(c analyzer.CrownJewelRisk) any { return c.Label })},
			"compromiseProbability": &graphql.Field{Type: graphql.Float, Resolve: field[analyzer.CrownJewelRisk](func(c analyzer.CrownJewelRisk) any { return c.CompromiseProbability })},
			"ciLow":                 &graphql.Field{Type: graphql.Float, Resolve: field[analyzer.CrownJewelRisk](func(c analyzer.CrownJewelRisk) any { return c.CILow })},
			"ciHigh":                &graphql.Field{Type: graphql.Float, Resolve: field[analyzer.CrownJewelRisk](func(c analyzer.CrownJewelRisk) any { return c.CIHigh })},
		},
	})

	riskSimulationType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "RiskSimulation",
		Description: "Monte Carlo risk quantification: per-trial edge realization → P(crown jewel reachable). Captures path multiplicity and shared edges that the per-path product can't.",
		Fields: graphql.Fields{
			"iterations":               &graphql.Field{Type: graphql.Int, Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.Iterations })},
			"anyCompromiseProbability": &graphql.Field{Type: graphql.Float, Description: "P(at least one crown jewel is compromised).", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.AnyCompromiseProbability })},
			"anyCiLow":                 &graphql.Field{Type: graphql.Float, Description: "Sampling-error CI low (Wilson 95%).", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.AnyCILow })},
			"anyCiHigh":                &graphql.Field{Type: graphql.Float, Description: "Sampling-error CI high (Wilson 95%).", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.AnyCIHigh })},
			"sensitivityLow":           &graphql.Field{Type: graphql.Float, Description: "Any-compromise probability with edge probabilities scaled −30% (model/input uncertainty, not sampling).", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.SensitivityLow })},
			"sensitivityHigh":          &graphql.Field{Type: graphql.Float, Description: "Any-compromise probability with edge probabilities scaled +30%.", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.SensitivityHigh })},
			"expectedCompromised":      &graphql.Field{Type: graphql.Float, Description: "Mean number of crown jewels compromised per trial.", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.ExpectedCompromised })},
			"crownJewels":              &graphql.Field{Type: graphql.NewList(crownJewelRiskType), Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.CrownJewels })},
		},
	})

	whatIfResultType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "WhatIfResult",
		Description: "Before/after of cutting a set of edges: surviving paths and quantified risk, with common random numbers so the delta reflects the cut, not Monte Carlo noise.",
		Fields: graphql.Fields{
			"removedEdges":  &graphql.Field{Type: graphql.Int, Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.RemovedEdges })},
			"before":        &graphql.Field{Type: graphql.NewList(pathType), Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.Before })},
			"after":         &graphql.Field{Type: graphql.NewList(pathType), Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.After })},
			"beforeRisk":    &graphql.Field{Type: riskSimulationType, Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.BeforeRisk })},
			"afterRisk":     &graphql.Field{Type: riskSimulationType, Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.AfterRisk })},
			"riskReduction": &graphql.Field{Type: graphql.Float, Description: "Drop in P(any crown jewel compromised) the cuts achieve.", Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.RiskReduction() })},
		},
	})

	statusType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "Status",
		Description: "Cheap analysis fingerprint for clients that poll to decide whether to refetch the full dashboard (avoids re-sending the whole graph every few seconds).",
		Fields: graphql.Fields{
			"version":     &graphql.Field{Type: graphql.String, Description: "Monotonic graph write version; changes when the graph changed.", Resolve: field[analyzer.Status](func(s analyzer.Status) any { return strconv.FormatInt(s.Version, 10) })},
			"passes":      &graphql.Field{Type: graphql.Int, Resolve: field[analyzer.Status](func(s analyzer.Status) any { return int(s.Passes) })},
			"paths":       &graphql.Field{Type: graphql.Int, Resolve: field[analyzer.Status](func(s analyzer.Status) any { return s.Paths })},
			"analyzedAt":  &graphql.Field{Type: graphql.String, Resolve: field[analyzer.Status](func(s analyzer.Status) any { return s.AnalyzedAt.UTC().Format(time.RFC3339) })},
			"prunedNodes": &graphql.Field{Type: graphql.Int, Description: "Lifetime stale nodes removed by the TTL pruner (0 when pruning is off).", Resolve: field[analyzer.Status](func(s analyzer.Status) any { return s.PrunedNodes })},
			"prunedEdges": &graphql.Field{Type: graphql.Int, Description: "Lifetime stale edges removed by the TTL pruner.", Resolve: field[analyzer.Status](func(s analyzer.Status) any { return s.PrunedEdges })},
			"lastPrunedAt": &graphql.Field{Type: graphql.String, Description: "When the pruner last removed something (empty when it never has).", Resolve: field[analyzer.Status](func(s analyzer.Status) any {
				if s.LastPrunedAt.IsZero() {
					return nil
				}
				return s.LastPrunedAt.UTC().Format(time.RFC3339)
			})},
		},
	})

	posturePointType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "PosturePoint",
		Description: "One sample of the exposure trend over time.",
		Fields: graphql.Fields{
			"at":            &graphql.Field{Type: graphql.String, Resolve: field[history.PosturePoint](func(p history.PosturePoint) any { return p.At.UTC().Format(time.RFC3339) })},
			"criticalPaths": &graphql.Field{Type: graphql.Int, Resolve: field[history.PosturePoint](func(p history.PosturePoint) any { return p.CriticalPaths })},
			"riskPct":       &graphql.Field{Type: graphql.Float, Description: "P(any crown jewel compromised) × 100 at that time.", Resolve: field[history.PosturePoint](func(p history.PosturePoint) any { return p.RiskPct })},
		},
	})

	historyType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "History",
		Description: "The temporal view: the exposure trend plus MTTR and open-path aging - what a point-in-time scanner can't tell you.",
		Fields: graphql.Fields{
			"trend":         &graphql.Field{Type: graphql.NewList(posturePointType), Resolve: field[historyView](func(h historyView) any { return h.Trend })},
			"openPaths":     &graphql.Field{Type: graphql.Int, Resolve: field[historyView](func(h historyView) any { return h.Stats.OpenPaths })},
			"resolvedPaths": &graphql.Field{Type: graphql.Int, Resolve: field[historyView](func(h historyView) any { return h.Stats.ResolvedPaths })},
			"mttrSeconds": &graphql.Field{Type: graphql.Float, Description: "Mean time-to-remediate: average seconds a resolved path stayed open. Null when nothing has resolved yet.", Resolve: field[historyView](func(h historyView) any {
				if h.Stats.MTTRCount == 0 {
					return nil
				}
				return h.Stats.MTTRSeconds
			})},
			"oldestOpenSince": &graphql.Field{Type: graphql.String, Description: "first_seen of the longest-open path (RFC3339); null when nothing is open.", Resolve: field[historyView](func(h historyView) any {
				if h.Stats.OldestOpenSince == nil {
					return nil
				}
				return h.Stats.OldestOpenSince.UTC().Format(time.RFC3339)
			})},
			"persistent": &graphql.Field{Type: graphql.Boolean, Description: "Whether history is file-backed (survives restarts).", Resolve: field[historyView](func(h historyView) any { return h.Persistent })},
		},
	})

	validationMetricsType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "ValidationMetrics",
		Description: "Evidence-based trust over the *validated* subset of paths (NOT a global claim): precision = confirmed/(confirmed+refuted), recall = confirmed/(confirmed+missed).",
		Fields: graphql.Fields{
			"confirmed": &graphql.Field{Type: graphql.Int, Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Confirmed })},
			"refuted":   &graphql.Field{Type: graphql.Int, Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Refuted })},
			"partial":   &graphql.Field{Type: graphql.Int, Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Partial })},
			"missed":    &graphql.Field{Type: graphql.Int, Description: "Real paths a tester found that the engine did NOT surface (false negatives).", Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Missed })},
			"tested":    &graphql.Field{Type: graphql.Int, Description: "Paths the engine surfaced and that were tested (confirmed+refuted+partial).", Resolve: field[validation.Metrics](func(m validation.Metrics) any { return m.Tested })},
			"precision": &graphql.Field{Type: graphql.Float, Description: "confirmed/(confirmed+refuted); null until any path is confirmed or refuted.", Resolve: field[validation.Metrics](func(m validation.Metrics) any {
				if m.Confirmed+m.Refuted == 0 {
					return nil
				}
				return m.Precision
			})},
			"recall": &graphql.Field{Type: graphql.Float, Description: "confirmed/(confirmed+missed); null until a confirmed or missed verdict exists.", Resolve: field[validation.Metrics](func(m validation.Metrics) any {
				if m.Confirmed+m.Missed == 0 {
					return nil
				}
				return m.Recall
			})},
		},
	})

	edgeCutInput := graphql.NewInputObject(graphql.InputObjectConfig{
		Name:        "EdgeCutInput",
		Description: "An edge to remove in a what-if. `from`/`to` accept a node id or name; `type` is optional (empty matches any edge between the pair).",
		Fields: graphql.InputObjectConfigFieldMap{
			"from": &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
			"to":   &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
			"type": &graphql.InputObjectFieldConfig{Type: graphql.String},
		},
	})

	query := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"attackPaths": &graphql.Field{
				Type:        graphql.NewList(pathType),
				Description: "Critical attack paths from the latest analysis pass, ranked by composite triage priority (P1 first), so limit:N is the actionable Top-N. Optionally scoped to one application and capped.",
				Args: graphql.FieldConfigArgument{
					"app":   &graphql.ArgumentConfig{Type: graphql.String, Description: "Only paths touching this application (repo_slug or app tag)."},
					"limit": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					paths := a.scopedLatest(p.Context)
					app, _ := p.Args["app"].(string)
					if app != "" {
						filtered := paths[:0:0]
						for _, ap := range paths {
							if pathMatchesApp(ap, app) {
								filtered = append(filtered, ap)
							}
						}
						paths = filtered
					}
					if limit, _ := p.Args["limit"].(int); limit > 0 && limit < len(paths) {
						paths = paths[:limit]
					}
					a.auditView(p.Context, "view.attack_paths", map[string]any{
						"count": len(paths), "app": app, "paths": pathIDsCapped(paths, 200),
					})
					return paths, nil
				},
			},
			"applications": &graphql.Field{
				Type:        graphql.NewList(graphql.String),
				Description: "Distinct application identifiers in the graph (repo slugs and app tags), for scoping queries.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					snap, err := a.snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					return applications(snap), nil
				},
			},
			"remediationPlan": &graphql.Field{
				Type:        graphql.NewList(fixType),
				Description: "Optimized remediation plan: the fewest fixes that eliminate the most critical-path risk, ranked (greedy choke-point set-cover). Optionally scoped to one application.",
				Args: graphql.FieldConfigArgument{
					"app": &graphql.ArgumentConfig{Type: graphql.String, Description: "Only consider paths touching this application."},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					paths := a.scopedLatest(p.Context)
					if app, _ := p.Args["app"].(string); app != "" {
						filtered := paths[:0:0]
						for _, ap := range paths {
							if pathMatchesApp(ap, app) {
								filtered = append(filtered, ap)
							}
						}
						paths = filtered
					}
					return remediation.Plan(paths), nil
				},
			},
			"invariantViolations": &graphql.Field{
				Type:        graphql.NewList(violationType),
				Description: "Architectural policy invariants currently violated.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					v := a.analyzer.Violations(tenantOf(p.Context))
					apps := allowedApps(p.Context)
					if len(apps) == 0 {
						return v, nil
					}
					out := v[:0:0]
					for _, viol := range v {
						for _, n := range viol.Nodes {
							if nodeMatchesAnyApp(n, apps) {
								out = append(out, viol)
								break
							}
						}
					}
					return out, nil
				},
			},
			"search": &graphql.Field{
				Type:        graphql.NewList(hitType),
				Description: "Full-text search across indexed assets and findings (requires OpenSearch).",
				Args: graphql.FieldConfigArgument{
					"query": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"size":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 25},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					hits, err := a.search.Search(p.Context, tenantOf(p.Context), p.Args["query"].(string), p.Args["size"].(int))
					if err != nil {
						return nil, err
					}
					apps := allowedApps(p.Context)
					if len(apps) == 0 {
						return hits, nil
					}
					// App-scoped: keep only hits for assets in the caller's scoped
					// snapshot, so search can't reveal other applications' assets.
					snap, err := a.snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					allowed := make(map[string]bool, len(snap.Nodes))
					for _, n := range snap.Nodes {
						allowed[n.ID] = true
					}
					out := hits[:0]
					for _, h := range hits {
						if allowed[h.ID] {
							out = append(out, h)
						}
					}
					return out, nil
				},
			},
			"posture": &graphql.Field{
				Type:        postureType,
				Description: "High-level posture summary for the overview dashboard.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					snap, err := a.snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					tenant := tenantOf(p.Context)
					paths := a.scopedLatest(p.Context)
					suppressed := a.suppress.ActiveSet(tenant)
					runtime := 0
					suppressedCount := 0
					kevOnPaths := map[string]bool{}
					for _, ap := range paths {
						if _, ok := suppressed[ap.ID]; ok {
							suppressedCount++
							continue // a triaged-off path doesn't count toward live exposure
						}
						if ap.RuntimeConfirmed {
							runtime++
						}
						for _, node := range ap.Nodes {
							if node.Label == ontology.LabelCVE && node.Bool(ontology.PropKEV) {
								kevOnPaths[node.ID] = true
							}
						}
					}
					return map[string]any{
						"criticalPaths":    len(paths),
						"activePaths":      len(paths) - suppressedCount,
						"suppressedPaths":  suppressedCount,
						"runtimeConfirmed": runtime,
						"kevOnPaths":       len(kevOnPaths),
						"policyViolations": len(a.analyzer.Violations(tenant)),
						"nodes":            len(snap.Nodes),
						"edges":            len(snap.Edges),
					}, nil
				},
			},
			"status": &graphql.Field{
				Type:        statusType,
				Description: "Cheap analysis fingerprint; poll this and only refetch the full dashboard when it changes.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return a.analyzer.Status(tenantOf(p.Context)), nil
				},
			},
			"validation": &graphql.Field{
				Type:        validationMetricsType,
				Description: "Red-team/BAS validation metrics - precision/recall over the tested subset. The evidence that the engine is grounded against reality, not just modeled.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return a.validation.Metrics(tenantOf(p.Context)), nil
				},
			},
			"history": &graphql.Field{
				Type:        historyType,
				Description: "The temporal view: exposure trend over time, MTTR, and how long paths have been open - the management/accountability layer a point-in-time scan lacks.",
				Args: graphql.FieldConfigArgument{
					"points": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 200, Description: "How many recent trend samples to return (most recent last)."},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					tenant := tenantOf(p.Context)
					limit, _ := p.Args["points"].(int)
					return historyView{
						Trend:      a.history.Trend(tenant, limit),
						Stats:      a.history.Stats(tenant),
						Persistent: a.history.Persistent(),
					}, nil
				},
			},
			"searchEnabled": &graphql.Field{
				Type:        graphql.Boolean,
				Description: "Whether full-text search (OpenSearch) is configured. The UI uses this to tell “feature off” apart from “no matches”.",
				Resolve: func(graphql.ResolveParams) (any, error) {
					return a.search.Enabled(), nil
				},
			},
			"aiEnabled": &graphql.Field{
				Type:        graphql.Boolean,
				Description: "Whether the AI-native layer (ANTHROPIC_API_KEY) is configured. The UI uses this to show/hide the AI assistant, summary, and explain features.",
				Resolve: func(graphql.ResolveParams) (any, error) {
					return a.aiEnabled(), nil
				},
			},
			"riskSimulation": &graphql.Field{
				Type:        riskSimulationType,
				Description: "Monte Carlo quantification of crown-jewel compromise probability over the current graph.",
				Args: graphql.FieldConfigArgument{
					"iterations": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0, Description: "Trials (default 2000, capped at 50000)."},
					"seed":       &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 1, Description: "RNG seed for reproducibility."},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					iters, _ := p.Args["iterations"].(int)
					seed, _ := p.Args["seed"].(int)
					// Default args → serve the cached per-pass simulation (the
					// dashboard's hot path); custom args → compute on demand.
					if iters <= 0 && seed == 1 {
						return a.analyzer.LatestRisk(tenantOf(p.Context)), nil
					}
					snap, err := a.snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					if iters > maxRiskIterations {
						iters = maxRiskIterations
					}
					return analyzer.SimulateRisk(snap, iters, uint64(seed)), nil // #nosec G115 -- PRNG seed; any 64-bit value is acceptable
				},
			},
			"kShortestPaths": &graphql.Field{
				Type:        graphql.NewList(pathType),
				Description: "The top-k highest-probability routes to a crown jewel (Yen's algorithm), so cutting the single best path doesn't hide the alternates.",
				Args: graphql.FieldConfigArgument{
					"target": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String), Description: "Crown-jewel node id or name."},
					"from":   &graphql.ArgumentConfig{Type: graphql.String, Description: "Optional seed node id or name; default = every internet-exposed seed."},
					"k":      &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 5},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					snap, err := a.snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					targetRef := p.Args["target"].(string)
					target := resolveNodeRef(snap, targetRef)
					from, _ := p.Args["from"].(string)
					k, _ := p.Args["k"].(int)
					paths := analyzer.KShortestToTarget(snap, resolveNodeRef(snap, from), target, k)
					a.auditView(p.Context, "view.attack_paths", map[string]any{
						"query": "kShortestPaths", "target": targetRef, "count": len(paths), "paths": pathIDsCapped(paths, 200),
					})
					return paths, nil
				},
			},
			"whatIf": &graphql.Field{
				Type:        whatIfResultType,
				Description: "Simulate cutting a set of edges (remediation): surviving attack paths and the quantified risk reduction.",
				Args: graphql.FieldConfigArgument{
					"cuts":       &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(edgeCutInput)))},
					"iterations": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0},
					"seed":       &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 1},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					snap, err := a.snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					cuts := parseCuts(p.Args["cuts"], func(ref string) string { return resolveNodeRef(snap, ref) })
					iters, _ := p.Args["iterations"].(int)
					if iters > maxRiskIterations {
						iters = maxRiskIterations
					}
					seed, _ := p.Args["seed"].(int)
					return analyzer.WhatIf(snap, cuts, iters, uint64(seed)), nil // #nosec G115 -- PRNG seed; any 64-bit value is acceptable
				},
			},
			"graph": &graphql.Field{
				Type:        graphViewType,
				Description: "The node/edge view for graph visualization, optionally scoped to one application and paginated.",
				Args: graphql.FieldConfigArgument{
					"app":    &graphql.ArgumentConfig{Type: graphql.String, Description: "Keep the connected component(s) around this application's nodes."},
					"limit":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0},
					"offset": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					snap, err := a.snapshot(p.Context)
					if err != nil {
						return nil, err
					}
					nodes, edges := snap.Nodes, snap.Edges
					app, _ := p.Args["app"].(string)
					if app != "" {
						nodes, edges = filterByApp(snap, app)
					}
					limit, _ := p.Args["limit"].(int)
					offset, _ := p.Args["offset"].(int)
					nodes, edges = paginate(nodes, edges, limit, offset)
					a.auditView(p.Context, "view.graph", map[string]any{
						"nodes": len(nodes), "edges": len(edges), "app": app,
					})
					return map[string]any{"nodes": nodes, "edges": edges}, nil
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{Query: query})
}

// field adapts a typed accessor into a graphql resolver: one generic helper
// instead of a copy per source type.
func field[T any](f func(T) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(T)), nil }
}

// maxRiskIterations caps Monte Carlo work per request so a hostile `iterations`
// can't turn a query into a CPU-exhaustion vector.
const maxRiskIterations = 50000

// verifyIterations bounds the Monte Carlo work for the per-remediation
// verification, so selecting `verification` on a plan of several fixes stays
// cheap while still giving a meaningful risk delta.
const verifyIterations = 800

// verifyCut closes the remediation loop: it simulates removing the edge a fix
// severs (what-if over the current graph) and reports the proven effect - paths
// eliminated and risk reduction - so the dashboard can show "verified: removes N
// paths" instead of trusting the generator. Returns nil when the fix carries no
// structured cut edge.
func (a *API) verifyCut(ctx context.Context, cut remediation.CutEdge) (any, error) {
	if cut.From == "" || cut.To == "" {
		return nil, nil
	}
	snap, err := a.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	res := analyzer.WhatIf(snap,
		[]analyzer.EdgeCut{{From: cut.From, To: cut.To, Type: ontology.EdgeType(cut.Type)}},
		verifyIterations, 1)
	eliminated := len(res.Before) - len(res.After)
	rr := res.RiskReduction()
	return map[string]any{
		"removedEdges":     res.RemovedEdges,
		"pathsBefore":      len(res.Before),
		"pathsAfter":       len(res.After),
		"pathsEliminated":  eliminated,
		"riskReductionPct": rr * 100,
		"verified":         res.RemovedEdges > 0 && (eliminated > 0 || rr > 0.0005),
	}, nil
}

// resolveNodeRef maps a user-supplied node reference (id or name) to a node id.
// An id wins; otherwise the first name match; otherwise the literal is returned
// so callers may reference ids not present in the current snapshot.
func resolveNodeRef(snap graph.Snapshot, ref string) string {
	if ref == "" {
		return ""
	}
	for _, n := range snap.Nodes {
		if n.ID == ref {
			return ref
		}
	}
	for _, n := range snap.Nodes {
		if n.Name == ref {
			return n.ID
		}
	}
	return ref
}

// parseCuts converts the GraphQL [EdgeCutInput!] argument into analyzer cuts,
// resolving each endpoint reference (id or name) to a node id.
func parseCuts(raw any, resolve func(string) string) []analyzer.EdgeCut {
	list, _ := raw.([]any)
	cuts := make([]analyzer.EdgeCut, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		from, _ := m["from"].(string)
		to, _ := m["to"].(string)
		typ, _ := m["type"].(string)
		cuts = append(cuts, analyzer.EdgeCut{From: resolve(from), To: resolve(to), Type: ontology.EdgeType(typ)})
	}
	return cuts
}

// ── application scoping ─────────────────────────────────────────────
//
// The graph is environment-wide by design; "application" is a view over it. A
// node belongs to app X when its repo_slug (stamped by scanners/CI) or its
// `app` tag (cloud resources) equals X.

// ── per-principal application scoping (object-level RBAC) ───────────────

// allowedApps is the caller's application allowlist (empty = unrestricted).
func allowedApps(ctx context.Context) []string { return auth.PrincipalFromContext(ctx).Apps }

// snapshot returns the per-request graph snapshot, restricted to the caller's
// allowed applications when the principal is app-scoped. Every graph read funnels
// through here, so scoping is enforced once for all resolvers (graph, risk,
// applications, search-context, …).
func (a *API) snapshot(ctx context.Context) (graph.Snapshot, error) {
	snap, err := a.rawSnapshot(ctx)
	if err != nil {
		return snap, err
	}
	if apps := allowedApps(ctx); len(apps) > 0 {
		nodes, edges := filterByApps(snap, apps)
		return graph.Snapshot{Nodes: nodes, Edges: edges}, nil
	}
	return snap, nil
}

// scopedLatest is the analyzer's latest attack paths, restricted to the ones
// touching the caller's allowed applications. The single funnel for path reads.
func (a *API) scopedLatest(ctx context.Context) []analyzer.AttackPath {
	paths := a.analyzer.Latest(tenantOf(ctx))
	apps := allowedApps(ctx)
	if len(apps) == 0 {
		return paths
	}
	out := make([]analyzer.AttackPath, 0, len(paths))
	for _, p := range paths {
		if pathMatchesAnyApp(p, apps) {
			out = append(out, p)
		}
	}
	return out
}

func nodeMatchesApp(n ontology.Node, app string) bool {
	if s, _ := n.Properties[ontology.PropRepoSlug].(string); s == app {
		return true
	}
	if s, _ := n.Properties["app"].(string); s == app {
		return true
	}
	return false
}

func nodeMatchesAnyApp(n ontology.Node, apps []string) bool {
	for _, app := range apps {
		if nodeMatchesApp(n, app) {
			return true
		}
	}
	return false
}

func pathMatchesApp(p analyzer.AttackPath, app string) bool {
	return pathMatchesAnyApp(p, []string{app})
}

func pathMatchesAnyApp(p analyzer.AttackPath, apps []string) bool {
	for _, n := range p.Nodes {
		if nodeMatchesAnyApp(n, apps) {
			return true
		}
	}
	return false
}

// filterByApp keeps the connected component(s) around the nodes that belong to
// the app, so the filtered view still shows the app's blast radius.
func filterByApp(snap graph.Snapshot, app string) ([]ontology.Node, []ontology.Edge) {
	return filterByApps(snap, []string{app})
}

// filterByApps keeps the connected component(s) around nodes belonging to any of
// the apps (the union of their blast radii).
func filterByApps(snap graph.Snapshot, apps []string) ([]ontology.Node, []ontology.Edge) {
	adj := map[string][]string{}
	for _, e := range snap.Edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	keep := map[string]bool{}
	var stack []string
	for _, n := range snap.Nodes {
		if nodeMatchesAnyApp(n, apps) {
			stack = append(stack, n.ID)
		}
	}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if keep[id] {
			continue
		}
		keep[id] = true
		stack = append(stack, adj[id]...)
	}

	var nodes []ontology.Node
	for _, n := range snap.Nodes {
		if keep[n.ID] {
			nodes = append(nodes, n)
		}
	}
	var edges []ontology.Edge
	for _, e := range snap.Edges {
		if keep[e.From] && keep[e.To] {
			edges = append(edges, e)
		}
	}
	return nodes, edges
}

// applications lists the distinct app identifiers present in the snapshot.
func applications(snap graph.Snapshot) []string {
	set := map[string]bool{}
	for _, n := range snap.Nodes {
		if s, _ := n.Properties[ontology.PropRepoSlug].(string); s != "" {
			set[s] = true
		}
		if s, _ := n.Properties["app"].(string); s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// paginate slices nodes deterministically (sorted by id) and keeps only the
// edges whose endpoints survive.
func paginate(nodes []ontology.Node, edges []ontology.Edge, limit, offset int) ([]ontology.Node, []ontology.Edge) {
	if limit <= 0 && offset <= 0 {
		return nodes, edges
	}
	sorted := make([]ontology.Node, len(nodes))
	copy(sorted, nodes)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	if offset > len(sorted) {
		offset = len(sorted)
	}
	end := len(sorted)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	page := sorted[offset:end]

	keep := map[string]bool{}
	for _, n := range page {
		keep[n.ID] = true
	}
	var keptEdges []ontology.Edge
	for _, e := range edges {
		if keep[e.From] && keep[e.To] {
			keptEdges = append(keptEdges, e)
		}
	}
	return page, keptEdges
}
