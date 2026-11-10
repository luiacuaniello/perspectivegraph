package api

import (
	"errors"
	"strconv"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/policy"
	"github.com/luiacuaniello/perspectivegraph/internal/search"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The estate's posture over time: the merge gate's verdict, the analyzer's status and history, and what the feeds have delivered.

func (a *API) postureTypes(t *schemaTypes) {
	nodeType, edgeType, pathType := t.nodeType, t.edgeType, t.pathType

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

	// prVerdictType answers one question for a CI gate: what does the engine say about
	// THIS commit. It reports three states, not two, and the third is the reason it
	// exists: "analysed: false" means nothing from that commit has reached the graph yet,
	// which is NOT the same as "no attack path". A gate that could not tell those apart
	// would report a green light for a pipeline whose scanner output never arrived, which
	// is the false negative this whole product is built to make visible.
	prVerdictType := graphql.NewObject(graphql.ObjectConfig{
		Name: "PRVerdict",
		Fields: graphql.Fields{
			"slug": &graphql.Field{Type: graphql.String, Description: "Repository the verdict is about (\"owner/name\")."},
			"sha":  &graphql.Field{Type: graphql.String, Description: "Commit the verdict is about."},
			"analysed": &graphql.Field{
				Type:        graphql.Boolean,
				Description: "Whether anything carrying this commit has reached the graph. False means the engine has not seen it - treat that as UNKNOWN, never as safe.",
			},
			"criticalPaths": &graphql.Field{
				Type:        graphql.Int,
				Description: "How many critical attack paths pass through an asset stamped with this commit.",
			},
			"paths": &graphql.Field{
				Type:        graphql.NewList(pathType),
				Description: "Those paths, so a gate can report what it blocked on rather than only that it blocked.",
			},
			"analysedAt": &graphql.Field{
				Type: graphql.String,
				Description: "When the pass that produced criticalPaths ran (RFC 3339). A gate must ignore " +
					"a verdict older than its own ingest: the commit can be in the graph while the paths " +
					"still describe the estate as it was before it arrived, which reads as zero paths.",
			},
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

	profileCompromiseType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "ProfileCompromise",
		Description: "P(any crown jewel reachable) against one attacker profile (commodity/criminal/apt) - the environment-level counterpart of a path's profileScores.",
		Fields: graphql.Fields{
			"profile":     &graphql.Field{Type: graphql.String, Resolve: field[analyzer.ProfileCompromise](func(p analyzer.ProfileCompromise) any { return p.Profile })},
			"prior":       &graphql.Field{Type: graphql.Float, Resolve: field[analyzer.ProfileCompromise](func(p analyzer.ProfileCompromise) any { return p.Prior })},
			"probability": &graphql.Field{Type: graphql.Float, Description: "P(any crown jewel reached) with every edge conditioned on this attacker's capability.", Resolve: field[analyzer.ProfileCompromise](func(p analyzer.ProfileCompromise) any { return p.Probability })},
		},
	})

	riskSimulationType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "RiskSimulation",
		Description: "Monte Carlo risk quantification: per-trial edge realization → P(crown jewel reachable). Captures path multiplicity and shared edges that the per-path product can't.",
		Fields: graphql.Fields{
			"iterations":                   &graphql.Field{Type: graphql.Int, Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.Iterations })},
			"anyCompromiseProbability":     &graphql.Field{Type: graphql.Float, Description: "P(at least one crown jewel is compromised), sampling edges independently at the marginal probability (the independent baseline).", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.AnyCompromiseProbability })},
			"anyCiLow":                     &graphql.Field{Type: graphql.Float, Description: "Sampling-error CI low (Wilson 95%).", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.AnyCILow })},
			"anyCiHigh":                    &graphql.Field{Type: graphql.Float, Description: "Sampling-error CI high (Wilson 95%).", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.AnyCIHigh })},
			"sensitivityLow":               &graphql.Field{Type: graphql.Float, Description: "Low end of the input-uncertainty credible band: any-compromise probability when each edge is resampled from its Beta posterior (model/input uncertainty, not sampling).", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.SensitivityLow })},
			"sensitivityHigh":              &graphql.Field{Type: graphql.Float, Description: "High end of the Beta-resampled credible band.", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.SensitivityHigh })},
			"expectedCompromised":          &graphql.Field{Type: graphql.Float, Description: "Mean number of crown jewels compromised per trial.", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.ExpectedCompromised })},
			"mixtureCompromiseProbability": &graphql.Field{Type: graphql.Float, Description: "Correlation-aware headline: P(any crown jewel reached) marginalized over the attacker-profile mixture, Σ P(c)·R_c. anyCompromiseProbability assumes independent edges; this reintroduces the same latent-capability correlation the per-path mixture score reflects, so headline and path scores are consistent.", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.MixtureCompromiseProbability })},
			"profileCompromise":            &graphql.Field{Type: graphql.NewList(profileCompromiseType), Description: "Per-attacker-profile compromise probability - \"80% vs an APT, 20% vs commodity\" at the environment level.", Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.ProfileCompromise })},
			"crownJewels":                  &graphql.Field{Type: graphql.NewList(crownJewelRiskType), Resolve: field[analyzer.RiskSimulation](func(s analyzer.RiskSimulation) any { return s.CrownJewels })},
		},
	})

	whatIfResultType := graphql.NewObject(graphql.ObjectConfig{
		Name:        "WhatIfResult",
		Description: "Before/after of cutting a set of edges: surviving paths and quantified risk. Both simulations run the same trials (common random numbers), so the delta is the cut's own effect, not Monte Carlo noise: never negative, and exactly 0 for an edge no route crosses.",
		Fields: graphql.Fields{
			"removedEdges":      &graphql.Field{Type: graphql.Int, Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.RemovedEdges })},
			"before":            &graphql.Field{Type: graphql.NewList(pathType), Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.Before })},
			"after":             &graphql.Field{Type: graphql.NewList(pathType), Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.After })},
			"beforeRisk":        &graphql.Field{Type: riskSimulationType, Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.BeforeRisk })},
			"afterRisk":         &graphql.Field{Type: riskSimulationType, Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.AfterRisk })},
			"riskReduction":     &graphql.Field{Type: graphql.Float, Description: "Drop in P(any crown jewel compromised) the cuts achieve. Saturates while one jewel is compromised in every trial (open to anyone) - see expectedReduction.", Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.RiskReduction() })},
			"expectedReduction": &graphql.Field{Type: graphql.Float, Description: "Drop in the expected number of crown jewels compromised: moves for every jewel the cuts protect.", Resolve: field[analyzer.WhatIfResult](func(r analyzer.WhatIfResult) any { return r.ExpectedReduction() })},
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

	t.violationType = violationType
	t.hitType = hitType
	t.graphViewType = graphViewType
	t.prVerdictType = prVerdictType
	t.postureType = postureType
	t.crownJewelRiskType = crownJewelRiskType
	t.profileCompromiseType = profileCompromiseType
	t.riskSimulationType = riskSimulationType
	t.whatIfResultType = whatIfResultType
	t.statusType = statusType
	t.posturePointType = posturePointType
	t.historyType = historyType
}

func (a *API) postureQueries(t *schemaTypes) graphql.Fields {
	prVerdictType, postureType, statusType, historyType, ingestSourceType := t.prVerdictType, t.postureType, t.statusType, t.historyType, t.ingestSourceType
	return graphql.Fields{
		"posture": &graphql.Field{
			Type:        postureType,
			Description: "High-level posture summary for the overview dashboard.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				v := a.view(p.Context)
				snap, err := v.snapshot()
				if err != nil {
					return nil, err
				}
				paths := v.latest()
				suppressed, err := v.suppressions()
				if err != nil {
					return nil, err
				}
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
					"policyViolations": v.violationCount(),
					"nodes":            len(snap.Nodes),
					"edges":            len(snap.Edges),
				}, nil
			},
		},
		"status": &graphql.Field{
			Type:        statusType,
			Description: "Cheap analysis fingerprint; poll this and only refetch the full dashboard when it changes.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				return a.view(p.Context).status(), nil
			},
		},
		"history": &graphql.Field{
			Type:        historyType,
			Description: "The temporal view: exposure trend over time, MTTR, and how long paths have been open - the management/accountability layer a point-in-time scan lacks.",
			Args: graphql.FieldConfigArgument{
				"points": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 200, Description: "How many recent trend samples to return (most recent last)."},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				limit, _ := p.Args["points"].(int)
				return a.view(p.Context).postureHistory(limit), nil
			},
		},
		"ingestBatch": &graphql.Field{
			Type: graphql.NewObject(graphql.ObjectConfig{
				Name:        "IngestBatch",
				Description: "How much of one ingest request has reached the graph. A large report is split into several messages, and an analyzer pass can run between them; appliedAt is set once the last one landed, so a verdict analysed after it saw the whole report.",
				Fields: graphql.Fields{
					"id":        &graphql.Field{Type: graphql.String},
					"messages":  &graphql.Field{Type: graphql.Int, Description: "Messages the request was sent as."},
					"applied":   &graphql.Field{Type: graphql.Int, Description: "Messages applied to the graph so far."},
					"complete":  &graphql.Field{Type: graphql.Boolean},
					"appliedAt": &graphql.Field{Type: graphql.String, Description: "When the last message was applied (RFC 3339), once complete."},
				},
			}),
			Description: "Progress of an ingest batch, by the id the ingest response returned. Null for an unknown or expired id, or one sent by another tenant.",
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				// A batch belongs to the tenant that sent it. Another tenant gets the
				// same null as an unknown id, so it learns nothing about it.
				st, ok, err := a.view(p.Context).batch(p.Args["id"].(string))
				if err != nil || !ok {
					return nil, err
				}
				out := map[string]any{
					"id": st.ID, "messages": st.Messages, "applied": st.Applied, "complete": st.Complete(),
				}
				if st.Complete() {
					out["appliedAt"] = st.AppliedAt.UTC().Format(time.RFC3339Nano)
				}
				return out, nil
			},
		},
		"ingestCoverage": &graphql.Field{
			Type:        graphql.NewList(ingestSourceType),
			Description: "What this engine has actually been fed, per collector, most recent first. Read it beside an empty board: 'no attack path' means none in what was ingested, and this says what that was - and which sources have gone quiet.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				return a.view(p.Context).feeds(), nil
			},
		},
		"prVerdict": &graphql.Field{
			Type:        prVerdictType,
			Description: "What the engine says about one commit, for a CI gate. Reports whether the commit was analysed at all, separately from whether it is clean.",
			Args: graphql.FieldConfigArgument{
				"slug": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String), Description: "Repository, \"owner/name\"."},
				"sha":  &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String), Description: "Commit SHA, as sent to the ingest webhook."},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				slug, _ := p.Args["slug"].(string)
				sha, _ := p.Args["sha"].(string)
				if slug == "" || sha == "" {
					return nil, errors.New("prVerdict: slug and sha are required")
				}

				// "Analysed" is answered from the GRAPH, not from the paths: an asset
				// carrying this commit may exist and reach nothing, which is the clean
				// case and must not look like the never-ingested case.
				v := a.view(p.Context)
				snap, err := v.snapshot()
				if err != nil {
					return nil, err
				}
				analysed := false
				for _, n := range snap.Nodes {
					if stampedWith(n.Properties, slug, sha) {
						analysed = true
						break
					}
				}

				var hit []analyzer.AttackPath
				for _, ap := range v.latest() {
					for _, n := range ap.Nodes {
						if stampedWith(n.Properties, slug, sha) {
							hit = append(hit, ap)
							break
						}
					}
				}
				// Dating the pass is what makes the answer safe to act on. Without it a
				// gate cannot distinguish "no path from this commit" from "the paths
				// predate this commit", and the second one reads as zero.
				analysedAt := ""
				if at := v.status().AnalyzedAt; !at.IsZero() {
					analysedAt = at.UTC().Format(time.RFC3339Nano)
				}
				return map[string]any{
					"slug": slug, "sha": sha,
					"analysed": analysed, "criticalPaths": len(hit), "paths": hit,
					"analysedAt": analysedAt,
				}, nil
			},
		},
	}
}
