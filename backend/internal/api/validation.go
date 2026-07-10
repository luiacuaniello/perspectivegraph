package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// validationRequest is the POST /validations body - one red-team/BAS verdict.
type validationRequest struct {
	PathID   string `json:"pathId"`
	Outcome  string `json:"outcome"` // confirmed | refuted | partial | missed
	Source   string `json:"source"`  // BAS tool / tester
	Evidence string `json:"evidence"`
	Route    string `json:"route"`
	// Detected (optional, for a confirmed verdict): was the attempt caught/blocked by
	// a defense (EDR/WAF/SOC)? Feeds the detection axis of the calibration diagnostics.
	Detected *bool `json:"detected"`
	// Scope declares what was validated: "path" (default) grades this specific path's
	// score S(P); "target" grades the per-target compromise probability - the right
	// quantity when the tester reports "I reached the crown jewel" (by any route)
	// rather than "I walked exactly this path".
	Scope string `json:"scope"`
	// Offline/self-test fallback: when the referenced path is NOT in the live analysis
	// (e.g. a synthetic verdict from `genverdicts`), these client-supplied calibration
	// features are used. For a live path the server-captured values always win, so a
	// real tester still can't fudge the prediction they're being graded against.
	PredictedScore      *float64 `json:"predictedScore"`
	PredictedCompromise *float64 `json:"predictedCompromise"`
	Hops                *int     `json:"hops"`
	CorrelatedHops      *bool    `json:"correlatedHops"`
	// WeightBasis (offline fallback): the path's weakest evidence basis, for per-basis
	// recalibration. Ignored when the path is live (server-captured wins).
	WeightBasis string `json:"weightBasis"`
}

// listValidations handles GET /validations - the verdicts board, the rolled-up
// precision/recall over the validated subset, and the calibration report (does a
// path scored 0.8 fire ~80% of the time). Viewer is enough.
func (a *API) listValidations(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"validations": a.validation.List(tenant),
		"metrics":     a.validation.Metrics(tenant),
		"calibration": a.validation.Calibration(tenant),
		"persistent":  a.validation.Persistent(),
	})
}

// pathFeatures returns the live scoring features of a surfaced path - its predicted
// score and the structure (hop count, correlated-hops flag) - so a recorded verdict
// can be paired with the prediction it tests AND segmented later. Zeroes when the
// path is no longer in the latest analysis (resolved, or never surfaced) or the
// analyzer isn't wired - such records sit out of the calibration math.
func (a *API) pathFeatures(tenant, pathID string) (score float64, hops int, correlated bool, weightBasis string, found bool) {
	if a.analyzer == nil || pathID == "" {
		return 0, 0, false, "", false
	}
	for _, p := range a.analyzer.Latest(tenant) {
		if p.ID == pathID {
			return p.Score, len(p.Steps), p.CorrelatedHops, weakestBasis(p), true
		}
	}
	return 0, 0, false, "", false
}

// weakestBasis is the basis of the path's least-evidenced hop (lowest WeightConfidence)
// - the provenance class calibration recalibrates the path under (a path is only as
// trustworthy as its weakest hop). Empty when no hop carries a basis.
func weakestBasis(p analyzer.AttackPath) string {
	basis, best := "", 2.0
	for _, st := range p.Steps {
		if st.WeightBasis != "" && st.WeightConfidence < best {
			basis, best = st.WeightBasis, st.WeightConfidence
		}
	}
	return basis
}

// targetCompromise returns the model's predicted probability that a surfaced path's
// crown-jewel *target* is reached at all (by any route) - the per-target Monte Carlo
// compromise probability. That is the quantity a target-scoped verdict is graded
// against (the any-route event), as opposed to the per-path S(P). Captured
// server-side so the tester can't fudge it; found=false when the path or its target
// is no longer live (the caller then trusts a client fallback, or omits it).
func (a *API) targetCompromise(tenant, pathID string) (prob float64, found bool) {
	if a.analyzer == nil || pathID == "" {
		return 0, false
	}
	var targetID string
	for _, p := range a.analyzer.Latest(tenant) {
		if p.ID == pathID {
			targetID = p.Target().ID
			break
		}
	}
	if targetID == "" {
		return 0, false
	}
	for _, cj := range a.analyzer.LatestRisk(tenant).CrownJewels {
		if cj.ID == targetID {
			return cj.CompromiseProbability, true
		}
	}
	return 0, false
}

// verdictFields is the resolved input for one verdict, shared by the single-verdict
// endpoint and the batch importer so both capture predictions the same way.
type verdictFields struct {
	pathID, outcome, scope, source, evidence, route string
	weightBasis                                     string
	detected                                        *bool
	predictedScore, predictedCompromise             *float64
	hops                                            *int
	correlatedHops                                  *bool
}

// buildRecord assembles a validation.Record, capturing the model's prediction and
// the path's structure server-side at verdict time (so a tester can't fudge the
// number they are graded against). When the path isn't live (a synthetic/offline
// verdict) it falls back to client-supplied features. For a target-scoped verdict it
// also captures the per-target compromise probability - the any-route event that
// track grades against.
func (a *API) buildRecord(tenant string, f verdictFields) validation.Record {
	score, hops, correlated, weightBasis, found := a.pathFeatures(tenant, f.pathID)
	if !found {
		if f.predictedScore != nil {
			score = *f.predictedScore
		}
		if f.hops != nil {
			hops = *f.hops
		}
		if f.correlatedHops != nil {
			correlated = *f.correlatedHops
		}
		if f.weightBasis != "" {
			weightBasis = f.weightBasis
		}
	}
	var compromise float64
	if validation.Scope(f.scope) == validation.ScopeTarget {
		if p, ok := a.targetCompromise(tenant, f.pathID); ok {
			compromise = p
		} else if f.predictedCompromise != nil {
			compromise = *f.predictedCompromise
		}
	}
	return validation.Record{
		PathID: f.pathID, Tenant: tenant, Outcome: validation.Outcome(f.outcome),
		Scope: validation.Scope(f.scope), Source: f.source, Evidence: f.evidence,
		Route: f.route, PredictedScore: score, PredictedCompromise: compromise,
		Hops: hops, CorrelatedHops: correlated, WeightBasis: weightBasis, Detected: f.detected,
	}
}

// matchPath resolves a live path id from a crown-jewel target name (and an optional
// entry filter), the way a BAS report references a finding when it does not carry an
// engine path id: the highest-priority surfaced path whose target name contains
// target and whose entry name contains from. Returns "" when nothing matches.
func (a *API) matchPath(tenant, target, from string) string {
	if a.analyzer == nil || target == "" {
		return ""
	}
	best, bestPri := "", -1.0
	for _, p := range a.analyzer.Latest(tenant) {
		if !containsFold(p.Target().Name, target) {
			continue
		}
		if from != "" && !containsFold(p.Source().Name, from) {
			continue
		}
		if p.Priority > bestPri {
			best, bestPri = p.ID, p.Priority
		}
	}
	return best
}

// putValidation handles POST /validations - record a verdict (a BAS run posts here,
// or a human records a manual test). Admin-only when auth is enabled.
func (a *API) putValidation(w http.ResponseWriter, r *http.Request) {
	if !a.adminWritable(r) {
		writeJSONError(w, http.StatusForbidden, "admin role required to record validations")
		return
	}
	var req validationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	tenant := tenantOf(r.Context())
	rec, err := a.validation.Put(a.buildRecord(tenant, verdictFields{
		pathID: req.PathID, outcome: req.Outcome, scope: req.Scope, source: req.Source,
		evidence: req.Evidence, route: req.Route, detected: req.Detected, weightBasis: req.WeightBasis,
		predictedScore: req.PredictedScore, predictedCompromise: req.PredictedCompromise,
		hops: req.Hops, correlatedHops: req.CorrelatedHops,
	}))
	if err != nil {
		switch {
		case errors.Is(err, validation.ErrInvalidOutcome),
			errors.Is(err, validation.ErrInvalidScope),
			errors.Is(err, validation.ErrMissingSource),
			errors.Is(err, validation.ErrMissingPathID):
			writeJSONError(w, http.StatusBadRequest, err.Error())
		default:
			writeJSONError(w, http.StatusInternalServerError, "could not record validation")
		}
		return
	}
	p := auth.PrincipalFromContext(r.Context())
	a.audit.Record("validation.put", p.Subject, p.Role.String(), p.Tenant, map[string]any{
		"id": rec.ID, "path": rec.PathID, "outcome": string(rec.Outcome), "source": rec.Source,
	})
	writeJSON(w, http.StatusOK, rec)
}

// importFinding is one verdict in a batch report - a superset of a single verdict
// that also allows referencing a live path by crown-jewel target (+ optional entry)
// when the BAS tool has no engine path id.
type importFinding struct {
	PathID              string   `json:"pathId"`
	Target              string   `json:"target"`
	From                string   `json:"from"`
	Outcome             string   `json:"outcome"`
	Scope               string   `json:"scope"`
	Detected            *bool    `json:"detected"`
	Route               string   `json:"route"`
	Evidence            string   `json:"evidence"`
	WeightBasis         string   `json:"weightBasis"`
	PredictedScore      *float64 `json:"predictedScore"`
	PredictedCompromise *float64 `json:"predictedCompromise"`
}

// importValidations handles POST /validations/import - the push path for automatic
// BAS verdict ingestion: a red-team/BAS platform's post-run webhook posts a whole
// report (a source + many findings) and the server matches each finding to a live
// path, captures the prediction, and records it - no per-finding round-trips and no
// client-side path matching. Admin-only. The response breaks findings into recorded,
// unmatched (a non-missed finding matched no live path - a legitimate gap), and
// rejected (the record was invalid, e.g. a bad outcome/scope - a client error); if
// nothing recorded and everything was rejected it answers 400, not a cheerful 200.
func (a *API) importValidations(w http.ResponseWriter, r *http.Request) {
	if !a.adminWritable(r) {
		writeJSONError(w, http.StatusForbidden, "admin role required to import validations")
		return
	}
	var req struct {
		Source   string          `json:"source"`
		Findings []importFinding `json:"findings"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Findings) == 0 {
		writeJSONError(w, http.StatusBadRequest, "report has no findings")
		return
	}
	tenant := tenantOf(r.Context())
	source := req.Source
	if source == "" {
		source = "bas-import"
	}
	// Three distinct outcomes, kept separate so a malformed report doesn't hide behind
	// "unmatched": recorded (stored), unmatched (a non-missed finding matched no live
	// path - a legitimate gap), and rejected (the record itself was invalid, e.g. a bad
	// outcome/scope - a client error worth surfacing).
	recorded, unmatched, rejected := 0, 0, 0
	for _, f := range req.Findings {
		pathID := f.PathID
		if pathID == "" && f.Outcome != string(validation.Missed) {
			pathID = a.matchPath(tenant, f.Target, f.From)
			if pathID == "" {
				unmatched++ // no live path to reference; not an error, just nothing to grade
				continue
			}
		}
		_, err := a.validation.Put(a.buildRecord(tenant, verdictFields{
			pathID: pathID, outcome: f.Outcome, scope: f.Scope, source: source,
			evidence: f.Evidence, route: f.Route, detected: f.Detected, weightBasis: f.WeightBasis,
			predictedScore: f.PredictedScore, predictedCompromise: f.PredictedCompromise,
		}))
		if err != nil {
			rejected++ // the finding matched (or carried) a path but was invalid
			continue
		}
		recorded++
	}
	p := auth.PrincipalFromContext(r.Context())
	a.audit.Record("validation.import", p.Subject, p.Role.String(), p.Tenant, map[string]any{
		"source": source, "recorded": recorded, "unmatched": unmatched, "rejected": rejected,
	})
	// Nothing stored and every finding was a client error ⇒ 400, so a broken integration
	// gets told rather than a cheerful 200 with zero effect.
	status := http.StatusOK
	if recorded == 0 && rejected > 0 && unmatched == 0 {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]any{"recorded": recorded, "unmatched": unmatched, "rejected": rejected})
}

// containsFold reports whether s contains sub, case-insensitively - the loose match
// a BAS report uses to reference a path by (partial) crown-jewel or entry name.
func containsFold(s, sub string) bool {
	return sub == "" || strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// deleteValidation handles DELETE /validations/{id}. Admin-only.
func (a *API) deleteValidation(w http.ResponseWriter, r *http.Request) {
	if !a.adminWritable(r) {
		writeJSONError(w, http.StatusForbidden, "admin role required to delete validations")
		return
	}
	if err := a.validation.Delete(tenantOf(r.Context()), r.PathValue("id")); err != nil {
		if errors.Is(err, validation.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "validation not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "could not delete validation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
