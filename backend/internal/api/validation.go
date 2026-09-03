package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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
	list, err := a.validation.List(r.Context(), tenant)
	if err != nil {
		// These records are the evidence every calibration number is computed from.
		// An empty board read from a broken store would read as "no verdicts yet",
		// which is a claim about the engine's accuracy nobody made.
		slog.Error("validation store access failed", "err", err)
		writeJSONError(w, http.StatusServiceUnavailable, "validation store unreachable - see the server log")
		return
	}
	metrics, err := a.validation.Metrics(r.Context(), tenant)
	if err != nil {
		slog.Error("validation store access failed", "err", err)
		writeJSONError(w, http.StatusServiceUnavailable, "validation store unreachable - see the server log")
		return
	}
	cal, err := a.validation.Calibration(r.Context(), tenant)
	if err != nil {
		slog.Error("validation store access failed", "err", err)
		writeJSONError(w, http.StatusServiceUnavailable, "validation store unreachable - see the server log")
		return
	}
	// The per-record board is scoped: a record names a path id, and a path id belongs to
	// an application.
	//
	// The aggregates below are NOT, and that is deliberate rather than an oversight.
	// They are tenant-wide measures of the ENGINE - precision/recall and calibration over
	// the validated subset - carrying no path id, asset name or application. They are
	// also computed in the store, which is shared by both backends so the two cannot
	// disagree about the dataset a calibration is derived from; recomputing a scoped
	// variant here would fork that math. And the same numbers are reachable through the
	// GraphQL `validation` and `calibration` fields, so withholding them here would be a
	// control that looks enforced and is not. Recorded as a residual in the threat model.
	if ids := a.scopedPathIDs(r.Context()); ids != nil {
		kept := make([]validation.Record, 0, len(list))
		for _, rec := range list {
			if ids[rec.PathID] {
				kept = append(kept, rec)
			}
		}
		list = kept
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"validations": list,
		"metrics":     metrics,
		"calibration": cal,
		"persistent":  a.validation.Persistent(),
	})
}

// pathFeatures returns the live scoring features of a surfaced path - its predicted
// score and the structure (hop count, correlated-hops flag) - so a recorded verdict
// can be paired with the prediction it tests AND segmented later. Zeroes when the
// path is no longer in the latest analysis (resolved, or never surfaced) or the
// analyzer isn't wired - such records sit out of the calibration math.
func (a *API) pathFeatures(ctx context.Context, pathID string) (score float64, hops int, correlated bool, weightBasis string, found bool) {
	if a.analyzer == nil || pathID == "" {
		return 0, 0, false, "", false
	}
	// scopedLatest, not analyzer.Latest: these helpers took the tenant alone, which let
	// an app-scoped caller read the score and structure of a path in another team's
	// application by naming its id.
	for _, p := range a.scopedLatest(ctx) {
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
func (a *API) targetCompromise(ctx context.Context, pathID string) (prob float64, found bool) {
	if a.analyzer == nil || pathID == "" {
		return 0, false
	}
	var targetID string
	for _, p := range a.scopedLatest(ctx) {
		if p.ID == pathID {
			targetID = p.Target().ID
			break
		}
	}
	if targetID == "" {
		return 0, false
	}
	for _, cj := range a.analyzer.LatestRisk(tenantOf(ctx)).CrownJewels {
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
func (a *API) buildRecord(ctx context.Context, f verdictFields) validation.Record {
	score, hops, correlated, weightBasis, found := a.pathFeatures(ctx, f.pathID)
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
		if p, ok := a.targetCompromise(ctx, f.pathID); ok {
			compromise = p
		} else if f.predictedCompromise != nil {
			compromise = *f.predictedCompromise
		}
	}
	return validation.Record{
		PathID: f.pathID, Tenant: tenantOf(ctx), Outcome: validation.Outcome(f.outcome),
		Scope: validation.Scope(f.scope), Source: f.source, Evidence: f.evidence,
		Route: f.route, PredictedScore: score, PredictedCompromise: compromise,
		Hops: hops, CorrelatedHops: correlated, WeightBasis: weightBasis, Detected: f.detected,
	}
}

// matchPath resolves a live path id from a crown-jewel target name (and an optional
// entry filter), the way a BAS report references a finding when it does not carry an
// engine path id: the highest-priority surfaced path whose target name contains
// target and whose entry name contains from. Returns "" when nothing matches.
// It resolves an id from a SUBSTRING of a crown-jewel name, so unscoped it was also an
// oracle: an app-scoped caller could enumerate the target names of other applications a
// letter at a time. It searches the caller's scoped paths.
func (a *API) matchPath(ctx context.Context, target, from string) string {
	if a.analyzer == nil || target == "" {
		return ""
	}
	best, bestPri := "", -1.0
	for _, p := range a.scopedLatest(ctx) {
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
	// A verdict recorded against another team's path pollutes the calibration that team
	// is graded by, and the features returned describe a path the caller cannot see.
	if !a.mayActOnPath(r.Context(), req.PathID) {
		writeJSONError(w, http.StatusNotFound, "attack path not found (or out of your scope)")
		return
	}
	rec, err := a.validation.Put(r.Context(), a.buildRecord(r.Context(), verdictFields{
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
	a.audit.Record(r.Context(), "validation.put", p.Subject, p.Role.String(), p.Tenant, map[string]any{
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
			pathID = a.matchPath(r.Context(), f.Target, f.From)
			if pathID == "" {
				unmatched++ // no live path to reference; not an error, just nothing to grade
				continue
			}
		}
		if !a.mayActOnPath(r.Context(), pathID) {
			unmatched++ // out of the caller's scope: indistinguishable from no live path
			continue
		}
		_, err := a.validation.Put(r.Context(), a.buildRecord(r.Context(), verdictFields{
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
	a.audit.Record(r.Context(), "validation.import", p.Subject, p.Role.String(), p.Tenant, map[string]any{
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
	// Addressed by record id, so the path it grades has to be resolved before the
	// mutation. Only for a scoped caller: an unrestricted one skips the read.
	if ids := a.scopedPathIDs(r.Context()); ids != nil {
		list, err := a.validation.List(r.Context(), tenantOf(r.Context()))
		if err != nil {
			slog.Error("validation store access failed", "err", err)
			writeJSONError(w, http.StatusServiceUnavailable, "validation store unreachable - see the server log")
			return
		}
		id := r.PathValue("id")
		found := false
		for _, rec := range list {
			if rec.ID == id && ids[rec.PathID] {
				found = true
				break
			}
		}
		if !found {
			writeJSONError(w, http.StatusNotFound, "validation not found (or out of your scope)")
			return
		}
	}
	if err := a.validation.Delete(r.Context(), tenantOf(r.Context()), r.PathValue("id")); err != nil {
		if errors.Is(err, validation.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "validation not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "could not delete validation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
