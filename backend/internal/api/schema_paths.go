package api

import (
	"context"
	"fmt"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/detection"
	"github.com/luiacuaniello/perspectivegraph/internal/remediation"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// Attack paths: how a route is shown, the fixes and detections generated for it, the triage records on it, and the queries that find routes, rank them and test a fix against them.

func (a *API) remediationTypes(t *schemaTypes) {
	remediationEffectType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "RemediationEffect",
		Description: "Closed-loop verification of a remediation: the result of simulating its removal (what-if) over the current graph - proof the fix cuts the path, not just a generated scaffold.",
		Fields: graphql.Fields{
			"removedEdges":      &graphql.Field{Type: graphql.Int, Description: "Graph edges the fix actually severs."},
			"pathsBefore":       &graphql.Field{Type: graphql.Int},
			"pathsAfter":        &graphql.Field{Type: graphql.Int},
			"pathsEliminated":   &graphql.Field{Type: graphql.Int, Description: "Critical paths removed by applying this fix."},
			"riskReductionPct":  &graphql.Field{Type: graphql.Float, Description: "Drop in P(any crown jewel compromised), in percentage points. Saturates: while one jewel is open to anyone it reads 0 for every other fix - see expectedReduction."},
			"expectedReduction": &graphql.Field{Type: graphql.Float, Description: "Drop in the expected number of crown jewels compromised - the per-jewel reductions added up. Measured on the same trials before and after, so it is never negative and is exactly 0 for a cut that protects nothing."},
			"verified":          &graphql.Field{Type: graphql.Boolean, Description: "True when simulating the fix removes the edge and it eliminates a path or reduces the expected number of compromised crown jewels."},
		},
	})

	cutEdgeType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "CutEdge",
		Description: "The edge of an attack path a fix severs.",
		Fields: graphql.Fields{
			"from": &graphql.Field{Type: graphql.String, Resolve: field[remediation.CutEdge](func(c remediation.CutEdge) any { return c.From })},
			"to":   &graphql.Field{Type: graphql.String, Resolve: field[remediation.CutEdge](func(c remediation.CutEdge) any { return c.To })},
			"type": &graphql.Field{Type: graphql.String, Description: "The edge type, e.g. EXPOSES.", Resolve: field[remediation.CutEdge](func(c remediation.CutEdge) any { return c.Type })},
		},
	})

	suggestionType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Remediation",
		Fields: graphql.Fields{
			"cut": &graphql.Field{
				Type:        cutEdgeType,
				Description: "The edge of the path this fix severs - where a reader should cut the kill chain.",
				Resolve: field[remediation.Suggestion](func(s remediation.Suggestion) any {
					if s.Cut.From == "" && s.Cut.To == "" {
						return nil
					}
					return s.Cut
				}),
			},
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

	t.remediationEffectType = remediationEffectType
	t.cutEdgeType = cutEdgeType
	t.suggestionType = suggestionType
	t.detectionType = detectionType
	t.fixType = fixType
}

func (a *API) pathTypes(t *schemaTypes) {
	nodeType, stepType, suggestionType, detectionType := t.nodeType, t.stepType, t.suggestionType, t.detectionType

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

	profileScoreType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "ProfileScore",
		Description: "A path's success probability against one attacker profile (commodity/criminal/apt): the conditional product ∏ p(e|c), with that profile's threat-model prior.",
		Fields: graphql.Fields{
			"profile": &graphql.Field{Type: graphql.String, Resolve: field[analyzer.ProfileScore](func(s analyzer.ProfileScore) any { return s.Profile })},
			"prior":   &graphql.Field{Type: graphql.Float, Description: "Threat-model weight P(c) for this profile (sums to 1 across profiles).", Resolve: field[analyzer.ProfileScore](func(s analyzer.ProfileScore) any { return s.Prior })},
			"score":   &graphql.Field{Type: graphql.Float, Description: "∏ p(e|c): how likely *this* attacker class walks the whole path.", Resolve: field[analyzer.ProfileScore](func(s analyzer.ProfileScore) any { return s.Score })},
		},
	})

	pathType := graphql.NewObject(graphql.ObjectConfig{
		Name: "AttackPath",
		Fields: graphql.Fields{
			"id":               &graphql.Field{Type: graphql.String, Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ID })},
			"score":            &graphql.Field{Type: graphql.Float, Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Score })},
			"runtimeConfirmed": &graphql.Field{Type: graphql.Boolean, Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.RuntimeConfirmed })},
			"directAccess":     &graphql.Field{Type: graphql.Boolean, Description: "True for a crown jewel the attacker holds without crossing an edge - a bucket anyone may read, a role any principal may assume. Its path is the jewel alone: no steps, score 1. Reachable is not held: an internet-facing database that still wants a password has no such path.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.DirectAccess })},
			"confidence":       &graphql.Field{Type: graphql.Float, Description: "How much to trust this path's score given how its edge weights were derived (mean hop weight-confidence, [0,1]).", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Confidence })},
			"confidenceLabel":  &graphql.Field{Type: graphql.String, Description: "Qualitative band for the score's trustworthiness: high|medium|low - an honest answer to \"why this %?\" instead of false precision.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ConfidenceLabel })},
			"scoreUpperBound":  &graphql.Field{Type: graphql.Float, Description: "The path score if its hops share a common cause rather than being independent: the weakest hop's probability (the comonotonic upper bound). The headline score multiplies hops as if independent - a lower bound under positive correlation - so the true exploitability lies in [score, scoreUpperBound]. A wide gap means the independence assumption matters.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ScoreUpperBound })},
			"correlatedHops":   &graphql.Field{Type: graphql.Boolean, Description: "True when two or more hops rest on the same weight basis - a concrete reason the hops may not be independent, so the score/scoreUpperBound band is grounded rather than theoretical. Does not change the score.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.CorrelatedHops })},
			"posteriorMean":    &graphql.Field{Type: graphql.Float, Description: "The mean of the ONE coherent posterior of the path's success probability: a single Monte Carlo composing epistemic uncertainty (each hop a Beta posterior) with the attacker-capability mixture (Σ_c P(c)·∏ p(e|c)). It is the point estimate [scoreCiLow, scoreCiHigh] brackets, and it even corrects the Jensen gap the plug-in mixtureScore ignores. It sits inside its interval, and with the default weak-attacker-weighted priors it also stays under scoreUpperBound (the Fréchet ceiling) - APT-heavy ATTACKER_PROFILE_PRIORS can lift it above. Being the attacker-marginal it can sit above or below the bare independent score depending on the profile priors.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.PosteriorMean })},
			"scoreCiLow":       &graphql.Field{Type: graphql.Float, Description: "Lower bound of the 90% credible interval of the unified posterior (posteriorMean): it composes *epistemic* uncertainty (each hop a Beta posterior whose width reflects its evidence) with the *attacker-capability* mixture, so one interval brackets the correlation-aware score rather than the bare independent product.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ScoreCILow })},
			"scoreCiHigh":      &graphql.Field{Type: graphql.Float, Description: "Upper bound of the 90% credible interval of the unified posterior (see scoreCiLow/posteriorMean). Wide ⇒ the score rests on soft inputs; narrow ⇒ evidence-backed. posteriorMean always lies inside.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ScoreCIHigh })},
			"mixtureScore":     &graphql.Field{Type: graphql.Float, Description: "The deterministic plug-in of the attacker-capability mixture, Σ P(c)·∏ p(e|c) at the point probabilities (the fast closed form; posteriorMean is its sampled, epistemic-aware counterpart). See profileScores for the per-profile breakdown.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.MixtureScore })},
			"profileScores":    &graphql.Field{Type: graphql.NewList(profileScoreType), Description: "Per-attacker-profile success probability ∏ p(e|c) with that profile's prior - the \"72% vs an APT, 18% vs commodity\" breakdown. A path trivial for an APT but hard for a commodity actor reads very differently here than from the single naive score. This is an interpretive lens, not the triage axis: the ordering to work through is `priority`.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.ProfileScores })},
			"priority":         &graphql.Field{Type: graphql.Float, Description: "Composite triage priority [0,100] blending exploitability (score) and trust (confidence) with corroboration (runtime-confirmed, KEV on path), target sensitivity (classified > tagged > inferred jewel), and entry blast radius. Paths are returned priority-first, so attackPaths(limit:N) is the actionable Top-N.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Priority })},
			"priorityLabel":    &graphql.Field{Type: graphql.String, Description: "Priority band: P1 (≥70) | P2 (≥40) | P3 - the \"fix these first\" bucket. A fact about the route (see priorityReason) lifts it to P1; a red-team/BAS verdict re-bands it where paths are listed: confirmed to P1, refuted to P3 unless a runtime alert or open access contradicts the test.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.PriorityLabel })},
			"priorityFactors":  &graphql.Field{Type: graphql.NewList(graphql.String), Description: "Human-readable reasons behind the priority (e.g. \"runtime-confirmed (active)\", \"KEV on path\", \"classified PII target\", \"entry shared by N paths\", \"confirmed by caldera\") - explainable triage, not a black-box rank.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.PriorityFactors })},
			"priorityReason": &graphql.Field{Type: graphql.String, Description: "Why the path is in its band, in one sentence, when a fact put it there rather than the blended number: a runtime alert on the route, an asset open to anyone, a known-exploited weakness on a likely route, a likely route on evidence into a high-value asset, or a red-team/BAS verdict. Null when the band is the blend's alone.", Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any {
				if p.PriorityReason == "" {
					return nil
				}
				return p.PriorityReason
			})},
			"nodes": &graphql.Field{Type: graphql.NewList(nodeType), Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return p.Nodes })},
			"steps": &graphql.Field{Type: graphql.NewList(stepType), Resolve: field[analyzer.AttackPath](func(p analyzer.AttackPath) any { return stepViews(p) })},
			"suppressed": &graphql.Field{
				Type:        graphql.Boolean,
				Description: "True when an in-force triage decision hides this path from the active board.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					ap := p.Source.(analyzer.AttackPath)
					_, ok, err := a.view(p.Context).suppression(ap.ID)
					if err != nil {
						return nil, err
					}
					return ok, nil
				},
			},
			"suppression": &graphql.Field{
				Type:        suppressionType,
				Description: "The triage decision in force for this path, if any.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					ap := p.Source.(analyzer.AttackPath)
					rec, ok, err := a.view(p.Context).suppression(ap.ID)
					if err != nil {
						return nil, err
					}
					if ok {
						return rec, nil
					}
					return nil, nil
				},
			},
			"firstSeen": &graphql.Field{
				Type:        graphql.String,
				Description: "When this path was first observed (RFC3339). Null until history has recorded a pass.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rec, ok := a.view(p.Context).pathHistory(p.Source.(analyzer.AttackPath).ID); ok {
						return rec.FirstSeen.UTC().Format(time.RFC3339), nil
					}
					return nil, nil
				},
			},
			"openForSeconds": &graphql.Field{
				Type:        graphql.Int,
				Description: "How long this path has been continuously open, in seconds (since first_seen of the current occurrence).",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rec, ok := a.view(p.Context).pathHistory(p.Source.(analyzer.AttackPath).ID); ok {
						return int(time.Since(rec.FirstSeen).Seconds()), nil
					}
					return nil, nil
				},
			},
			"reopens": &graphql.Field{
				Type:        graphql.Int,
				Description: "How many times this path resolved and then came back - a flapping/regression signal.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					if rec, ok := a.view(p.Context).pathHistory(p.Source.(analyzer.AttackPath).ID); ok {
						return rec.Reopens, nil
					}
					return 0, nil
				},
			},
			"ticket": &graphql.Field{
				Type:        ticketType,
				Description: "The open remediation ticket for this path, if one has been raised.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					tk, ok, err := a.view(p.Context).openTicket(p.Source.(analyzer.AttackPath).ID)
					if err != nil {
						return nil, err
					}
					if ok {
						return tk, nil
					}
					return nil, nil
				},
			},
			"validation": &graphql.Field{
				Type:        validationType,
				Description: "The latest red-team/BAS verdict on whether this path is real, if it has been tested.",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					v, ok, err := a.view(p.Context).verdict(p.Source.(analyzer.AttackPath).ID)
					if err != nil {
						return nil, err
					}
					if ok {
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

	edgeCutInput := graphql.NewInputObject(graphql.InputObjectConfig{
		Name:        "EdgeCutInput",
		Description: "An edge to remove in a what-if. `from`/`to` accept a node id or name; `type` is optional (empty matches any edge between the pair).",
		Fields: graphql.InputObjectConfigFieldMap{
			"from": &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
			"to":   &graphql.InputObjectFieldConfig{Type: graphql.NewNonNull(graphql.String)},
			"type": &graphql.InputObjectFieldConfig{Type: graphql.String},
		},
	})

	t.suppressionType = suppressionType
	t.ticketType = ticketType
	t.validationType = validationType
	t.profileScoreType = profileScoreType
	t.pathType = pathType
	t.edgeCutInput = edgeCutInput
}

func (a *API) pathQueries(t *schemaTypes) graphql.Fields {
	fixType, pathType, violationType, riskSimulationType, whatIfResultType, edgeCutInput := t.fixType, t.pathType, t.violationType, t.riskSimulationType, t.whatIfResultType, t.edgeCutInput
	return graphql.Fields{
		"attackPaths": &graphql.Field{
			Type:        graphql.NewList(pathType),
			Description: "Critical attack paths from the latest analysis pass, ranked by composite triage priority (P1 first), so limit:N is the actionable Top-N. Optionally scoped to one application and capped.",
			Args: graphql.FieldConfigArgument{
				"app":    &graphql.ArgumentConfig{Type: graphql.String, Description: "Only paths touching this application (repo_slug or app tag)."},
				"limit":  &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0, Description: "Return at most this many paths; 0 (the default) returns them all."},
				"offset": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 0, Description: "Skip this many paths from the top of the ranking before limit applies, so offset += limit pages through it. Past the end is an empty list."},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				paths := a.view(p.Context).shownPaths()
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
				// After the scope, before the cap: a page is a window on the ranking the
				// caller asked for, not on the whole environment's.
				if offset, _ := p.Args["offset"].(int); offset > 0 {
					paths = paths[min(offset, len(paths)):]
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
		"kShortestPaths": &graphql.Field{
			Type:        graphql.NewList(pathType),
			Description: "The top-k highest-probability routes to a crown jewel (Yen's algorithm), so cutting the single best path doesn't hide the alternates.",
			Args: graphql.FieldConfigArgument{
				"target": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String), Description: "Crown-jewel node id or name."},
				"from":   &graphql.ArgumentConfig{Type: graphql.String, Description: "Optional seed node id or name; default = every internet-exposed seed."},
				"k":      &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 5},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				snap, err := a.view(p.Context).snapshot()
				if err != nil {
					return nil, err
				}
				targetRef := p.Args["target"].(string)
				target := resolveNodeRef(snap, targetRef)
				from, _ := p.Args["from"].(string)
				k, _ := p.Args["k"].(int)
				// Clamp k. Yen's algorithm is O(k · n · (m + n log n)), so k is a
				// direct multiplier on server work supplied by the caller - the same
				// hazard `iterations` and `cuts` are already bounded against. It was
				// the one cost argument left unbounded.
				if k > maxShortestPaths {
					k = maxShortestPaths
				}
				fromID := resolveNodeRef(snap, from)
				v, err := a.heavy(p.Context, fmt.Sprintf("kshortest|%s|%s|%d", fromID, target, k), func(ctx context.Context) (any, error) {
					return analyzer.KShortestToTarget(ctx, snap, fromID, target, k)
				})
				if err != nil {
					return nil, err
				}
				paths := v.([]analyzer.AttackPath)
				a.auditView(p.Context, "view.attack_paths", map[string]any{
					"query": "kShortestPaths", "target": targetRef, "count": len(paths), "paths": pathIDsCapped(paths, 200),
				})
				return paths, nil
			},
		},
		"remediationPlan": &graphql.Field{
			Type:        graphql.NewList(fixType),
			Description: "Optimized remediation plan: the fewest fixes that eliminate the most critical-path risk, ranked (greedy choke-point set-cover). Optionally scoped to one application.",
			Args: graphql.FieldConfigArgument{
				"app":   &graphql.ArgumentConfig{Type: graphql.String, Description: "Only consider paths touching this application."},
				"title": &graphql.ArgumentConfig{Type: graphql.String, Description: "Return only the fix with this title - the way to ask for one fix's verification without paying for every fix's."},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				paths := a.view(p.Context).latest()
				if app, _ := p.Args["app"].(string); app != "" {
					filtered := paths[:0:0]
					for _, ap := range paths {
						if pathMatchesApp(ap, app) {
							filtered = append(filtered, ap)
						}
					}
					paths = filtered
				}
				plan := remediation.Plan(paths)
				// The plan is ranked over all paths first and filtered after, so the one
				// fix returned carries the same rank, coverage and cut as in the full plan.
				if title, _ := p.Args["title"].(string); title != "" {
					one := plan[:0:0]
					for _, f := range plan {
						if f.Suggestion.Title == title {
							one = append(one, f)
						}
					}
					plan = one
				}
				return plan, nil
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
				snap, err := a.view(p.Context).snapshot()
				if err != nil {
					return nil, err
				}
				cuts := parseCuts(p.Args["cuts"], func(ref string) string { return resolveNodeRef(snap, ref) })
				iters, _ := p.Args["iterations"].(int)
				if iters > maxRiskIterations {
					iters = maxRiskIterations
				}
				seed, _ := p.Args["seed"].(int)
				return a.heavy(p.Context, fmt.Sprintf("whatif|%v|%d|%d", cuts, iters, seed), func(ctx context.Context) (any, error) {
					return analyzer.WhatIf(ctx, snap, cuts, iters, uint64(seed)) // #nosec G115 -- PRNG seed; any 64-bit value is acceptable
				})
			},
		},
		"invariantViolations": &graphql.Field{
			Type:        graphql.NewList(violationType),
			Description: "Architectural policy invariants currently violated.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				return a.view(p.Context).violations(), nil
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
					return a.view(p.Context).latestRisk()
				}
				if iters > maxRiskIterations {
					iters = maxRiskIterations
				}
				// Read outside the analysis: the snapshot is cached for the whole request
				// by whoever loads it first, and a load under the analysis's deadline
				// could cache that deadline's error for every field after it.
				snap, err := a.view(p.Context).snapshot()
				if err != nil {
					return nil, err
				}
				return a.heavy(p.Context, fmt.Sprintf("risk|%d|%d", iters, seed), func(ctx context.Context) (any, error) {
					// The request's context, not Background: when the request is
					// abandoned or its deadline passes, the simulation stops instead of
					// running a core to completion for an answer nobody will read.
					return analyzer.SimulateRisk(ctx, snap, iters, uint64(seed)) // #nosec G115 -- PRNG seed; any 64-bit value is acceptable
				})
			},
		},
	}
}
