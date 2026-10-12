package mcp

// The output schemas: what each tool's result carries, and what the fields mean.
//
// An agent reads a tool's description before calling it and its result after. Between the
// two it plans - "list the routes, then explain the worst one" - and that plan names
// fields. With no output schema it names them by guessing, and learns it guessed wrong one
// call too late.
//
// The fields are the engine's own (the tools pass its GraphQL answer through), so these
// schemas could drift from what a tool really returns. `TestEveryMCPToolReturnsWhatItDeclares`
// runs every tool against the real engine and fails on a field returned and not declared,
// or declared and not returned.

// Every field of the engine's API is nullable, and a client that validates
// structuredContent against the schema would fail a call that succeeded if a field
// declared "number" arrived null. So each leaf admits null, and so does each list and
// nested object.
func leaf(typ, description string) map[string]any {
	s := map[string]any{"type": []any{typ, "null"}}
	if description != "" {
		s["description"] = description
	}
	return s
}

func text(description string) map[string]any   { return leaf("string", description) }
func number(description string) map[string]any { return leaf("number", description) }
func count(description string) map[string]any  { return leaf("integer", description) }
func flag(description string) map[string]any   { return leaf("boolean", description) }

func list(description string, items map[string]any) map[string]any {
	s := leaf("array", description)
	s["items"] = items
	return s
}

func record(description string, props map[string]any) map[string]any {
	s := leaf("object", description)
	s["properties"] = props
	return s
}

const estimate = " A modelled estimate, not a measured rate: see get_score_trust."

// The engine lists a suppressed route with the others and marks it. An agent that is not
// shown the mark presents as open work something an analyst has already decided about.
const suppressedNote = "True when an analyst has triaged the route off the board (accepted risk, false positive). It still exists, but do not present it as open work."

// routeSummary is the part of a route every listing tool returns.
func routeSummary() map[string]any {
	return map[string]any{
		"id":            text("Stable id of the route. Pass it to explain_attack_path."),
		"score":         number("End-to-end probability that an attacker completes the route, 0-1." + estimate),
		"priority":      number("Triage priority, 0-100: the score blended with corroboration, target sensitivity and how many routes share the entry point. This is the order of the list."),
		"priorityLabel": text("Priority band: P1, P2 or P3. P1 is what to fix first."),
	}
}

func pathNode(extra map[string]any) map[string]any {
	props := map[string]any{
		"name":  text("Asset name."),
		"label": text("Asset type, e.g. LoadBalancer, Container, IAM_Role, Bucket, CVE."),
	}
	for k, v := range extra {
		props[k] = v
	}
	return record("", props)
}

func postureOutput() map[string]any {
	return obj(map[string]any{
		"posture": record("Counts for the whole environment.", map[string]any{
			"criticalPaths":    count("Routes found by the latest analysis, suppressed ones included: the number list_attack_paths pages through."),
			"activePaths":      count("Routes still on the board, that is not suppressed."),
			"suppressedPaths":  count("Routes an analyst has triaged off the board (accepted risk, false positive)."),
			"runtimeConfirmed": count("Open routes with a runtime alert on them: an attack may be in progress."),
			"kevOnPaths":       count("Distinct known-exploited vulnerabilities (CISA KEV) sitting on a route."),
			"policyViolations": count("Violations of the policy invariants: rules the environment is never meant to break."),
			"nodes":            count("Assets in the graph."),
			"edges":            count("Relationships in the graph."),
		}),
		"riskSimulation": record("The environment's overall risk, simulated over every route at once.", map[string]any{
			"anyCompromiseProbability": number("Probability that at least one sensitive asset is reached, 0-1." + estimate),
			"sensitivityLow":           number("Low end of that probability when every hop is resampled within its uncertainty."),
			"sensitivityHigh":          number("High end of the same band."),
			"crownJewels": list("The sensitive assets, each with the probability that an attacker reaches it.", record("", map[string]any{
				"name":                  text("Asset name. Pass it to routes_to_target as `target`."),
				"label":                 text("Asset type, e.g. IAM_Role, Bucket, Database."),
				"compromiseProbability": number("Probability this asset is reached, 0-1." + estimate),
			})),
		}),
		"applications": list("The application names this environment knows: the values `app` arguments accept.", text("")),
	})
}

func listPathsOutput() map[string]any {
	route := routeSummary()
	route["priorityReason"] = text("One sentence saying why the route is in its band, when a fact put it there (a runtime alert, a known-exploited weakness); null when the blended number did.")
	route["priorityFactors"] = list("The reasons behind the priority, human-readable.", text(""))
	route["confidenceLabel"] = text("How far the score can be trusted given where its hop probabilities came from: high, medium or low.")
	route["runtimeConfirmed"] = flag("True when a runtime alert sits on the route.")
	route["suppressed"] = flag(suppressedNote)
	route["scoreUpperBound"] = number("The score if the hops fail or succeed together rather than independently: the weakest hop's probability. The truth lies between score and this.")
	route["correlatedHops"] = flag("True when two or more hops rest on the same kind of evidence, a concrete reason they may not be independent.")
	route["nodes"] = list("The assets the route passes through, entry point first, target last.", pathNode(map[string]any{
		"internetExposed": flag("True for an entry point reachable from the internet."),
		"crownJewel":      flag("True for a sensitive asset."),
	}))
	return obj(map[string]any{
		"attackPaths": list("The routes, highest priority first.", record("", route)),
		"offset":      map[string]any{"type": "integer", "description": "How many routes were skipped before this page."},
		"nextOffset":  count("Pass as `offset` for the next page. Null when this page is the last."),
	}, "attackPaths", "offset", "nextOffset")
}

func explainPathOutput() map[string]any {
	route := routeSummary()
	route["id"] = text("The route's id, as asked for.")
	route["priorityReason"] = text("One sentence saying why the route is in its band, when a fact put it there; null when the blended number did.")
	route["priorityFactors"] = list("The reasons behind the priority, human-readable.", text(""))
	route["runtimeConfirmed"] = flag("True when a runtime alert sits on the route.")
	route["suppressed"] = flag(suppressedNote)
	route["scoreUpperBound"] = number("The score if the hops fail or succeed together rather than independently: the weakest hop's probability.")
	route["correlatedHops"] = flag("True when two or more hops rest on the same kind of evidence.")
	route["confidence"] = number("How far the score can be trusted, 0-1: the mean confidence of its hops.")
	route["confidenceLabel"] = text("The same as a band: high, medium or low.")
	route["posteriorMean"] = number("The score with the uncertainty of each hop and the mix of attacker capabilities taken into account, 0-1.")
	route["scoreCiLow"] = number("Low end of the 90% credible interval around posteriorMean. A wide interval means the score rests on soft inputs.")
	route["scoreCiHigh"] = number("High end of the same interval.")
	route["mixtureScore"] = number("The score averaged over attacker profiles, weighted by how likely each is.")
	route["profileScores"] = list("The score against each attacker profile.", record("", map[string]any{
		"profile": text("Attacker profile: commodity, criminal or apt."),
		"prior":   number("How likely this profile is assumed to be, 0-1."),
		"score":   number("Probability this profile completes the route, 0-1."),
	}))
	route["nodes"] = list("The assets on the route, entry point first, target last.", pathNode(map[string]any{
		"id":              text("Node id: what steps and cuts refer to."),
		"internetExposed": flag("True for an entry point reachable from the internet."),
		"crownJewel":      flag("True for a sensitive asset."),
		"severity":        text("For a vulnerability: its severity."),
		"cvss":            number("For a vulnerability: its CVSS base score."),
		"kev":             flag("For a vulnerability: true when it is known to be exploited in the wild (CISA KEV)."),
	}))
	route["steps"] = list("The hops, in order. Each is one relationship an attacker crosses.", record("", map[string]any{
		"edgeType":         text("The relationship, e.g. EXPOSES, ASSUMES, HAS_PERMISSION, CAN_ESCALATE_TO."),
		"from":             text("Node id the hop starts at. Usable as `from` in a simulate_fix cut."),
		"to":               text("Node id the hop ends at. Usable as `to` in a simulate_fix cut."),
		"probability":      number("Probability an attacker crosses this hop, 0-1."),
		"weightBasis":      text("Where that probability came from: kev, epss or runtime are observed evidence; cvss, severity or heuristic are estimates."),
		"weightConfidence": number("How far to trust that probability, 0-1, given its basis."),
		"attack": record("The MITRE ATT&CK technique the hop maps to; null when none applies.", map[string]any{
			"id":     text("Technique id, e.g. T1190."),
			"name":   text("Technique name."),
			"tactic": text("The tactic it serves, e.g. Initial Access."),
		}),
	}))
	route["remediations"] = list("Ways to close the route.", record("", map[string]any{
		"title":     text("What to change, in a line."),
		"kind":      text("The form the fix takes, e.g. terraform."),
		"rationale": text("Why this closes the route."),
		"content":   text("The fix itself: the code or the policy to apply."),
		"cut": record("The relationship this fix removes; null when it removes none. Pass it to simulate_fix as one of `cuts` to see what the fix would do.", map[string]any{
			"from": text("Node id the relationship starts at."),
			"to":   text("Node id it ends at."),
			"type": text("The relationship type."),
		}),
	}))
	return obj(route, "id")
}

// A route here is not always one list_attack_paths knows: the engine ranks the best route
// from each entry point to each target, and the alternates exist only in this answer. So
// they carry their own hops, and no triage priority - the engine computes none for them,
// and a 0 passed through would read as "least urgent".
func routesOutput() map[string]any {
	return obj(map[string]any{
		"kShortestPaths": list("The distinct routes to the target, most likely first. Empty when nothing reaches it.", record("", map[string]any{
			"id":    text("Id of the route. explain_attack_path takes it only when list_attack_paths returns the same route; an alternate that exists only here is described by its steps below."),
			"score": number("End-to-end probability that an attacker completes the route, 0-1." + estimate),
			"nodes": list("The assets the route passes through, entry point first, target last. A node that appears in every route is a choke point.", pathNode(nil)),
			"steps": list("The hops, in order.", record("", map[string]any{
				"edgeType":    text("The relationship, e.g. EXPOSES, ASSUMES, HAS_PERMISSION, CAN_ESCALATE_TO."),
				"from":        text("Node id the hop starts at. Usable as `from` in a simulate_fix cut."),
				"to":          text("Node id the hop ends at. Usable as `to` in a simulate_fix cut."),
				"probability": number("Probability an attacker crosses this hop, 0-1."),
				"weightBasis": text("Where that probability came from: kev, epss or runtime are observed evidence; cvss, severity or heuristic are estimates."),
			})),
		})),
	})
}

func fixesOutput() map[string]any {
	return obj(map[string]any{
		"remediationPlan": list("The changes, the one that removes the most risk first.", record("", map[string]any{
			"title":       text("What to change, in a line."),
			"kind":        text("The form the fix takes, e.g. terraform."),
			"filename":    text("A suggested file name for the fix."),
			"rationale":   text("Why this change closes the routes it closes."),
			"pathCount":   count("How many routes this change cuts."),
			"riskCovered": number("The summed score of the routes it cuts."),
			"coveragePct": number("That sum as a share of the risk on all routes, 0-1."),
		})),
	})
}

func simulateOutput() map[string]any {
	risk := func(when string) map[string]any {
		return record("", map[string]any{
			"anyCompromiseProbability": number("Probability that at least one sensitive asset is reached " + when + ", 0-1." + estimate),
		})
	}
	return obj(map[string]any{
		"whatIf": record("The same environment with the cuts applied, compared with it as it is.", map[string]any{
			"removedEdges":  count("How many relationships the cuts matched. 0 means they matched nothing: check the node ids and the type."),
			"riskReduction": number("How much the probability that any sensitive asset is reached drops, 0-1. It stays 0 while one asset is still reached in every trial."),
			"beforeRisk":    risk("as things are"),
			"afterRisk":     risk("with the cuts applied"),
			"after": list("The routes still open with the cuts applied.", record("", map[string]any{
				"id": text("Route id."),
			})),
		}),
	})
}

func searchOutput() map[string]any {
	return obj(map[string]any{
		"search": map[string]any{
			"type":        "array",
			"description": "The matches, best first. Empty when nothing matches.",
			"items": record("", map[string]any{
				"id":    text("Node id: usable as `target` or `from` in routes_to_target and in simulate_fix cuts."),
				"name":  text("Asset or finding name."),
				"label": text("Its type, e.g. Container, IAM_Role, CVE."),
				"score": number("Relevance of the match. Comparable only within one result."),
			}),
		},
	}, "search")
}

func scoreTrustOutput() map[string]any {
	discrimination := func(what string) map[string]any {
		return record("Whether "+what+" puts confirmed routes above refuted ones.", map[string]any{
			"auc":       number("Probability that a confirmed route outranks a refuted one. 0.5 is a coin. Null until there is one of each."),
			"aucLow":    number("Low end of its approximate 95% interval."),
			"aucHigh":   number("High end. An interval containing 0.5 cannot be told from chance."),
			"verdict":   text("discriminates, indistinguishable-from-chance, inverted or insufficient-data."),
			"positives": count("Confirmed outcomes behind the figure."),
			"negatives": count("Refuted outcomes behind the figure."),
			"hasData":   flag("False when no outcome has been recorded."),
		})
	}
	return obj(map[string]any{
		"calibration": record("The scores compared with the recorded red-team and BAS outcomes.", map[string]any{
			"samples":                count("Tested routes that carried a score: the size of the sample."),
			"hasData":                flag("False when no outcome has been recorded: every score is then an expert estimate."),
			"verdict":                text("well-calibrated, calibrated-on-average, overconfident, underconfident or insufficient-data."),
			"diagnosis":              text("What to do about the gap, in one line."),
			"meanPredicted":          number("The mean score of the tested routes."),
			"observedRate":           number("The share of them that were confirmed."),
			"brier":                  number("Mean squared gap between score and outcome, 0-1. Lower is better."),
			"ece":                    number("Expected calibration error, 0-1. Lower is better."),
			"recommendedScale":       number("Observed rate over predicted: below 1 the scores run high, above 1 low. Null until the sample is large enough."),
			"discrimination":         discrimination("the score"),
			"priorityDiscrimination": discrimination("the triage order"),
		}),
		"validation": record("What happened to the routes that were tested.", map[string]any{
			"tested":    count("Routes the engine reported that were then tested."),
			"confirmed": count("Tested routes an attacker could really follow."),
			"refuted":   count("Tested routes that turned out not to work: false positives."),
			"partial":   count("Tested routes that worked in part."),
			"missed":    count("Real routes a tester found that the engine had not reported: false negatives."),
			"precision": number("confirmed / (confirmed + refuted). Null until one of the two exists."),
			"recall":    number("confirmed / (confirmed + missed). Null until one of the two exists."),
		}),
	})
}
