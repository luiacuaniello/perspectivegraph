package api

import (
	"encoding/json"
	"errors"
	"net/http"

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
	// Offline/self-test fallback: when the referenced path is NOT in the live analysis
	// (e.g. a synthetic verdict from `genverdicts`), these client-supplied calibration
	// features are used. For a live path the server-captured values always win, so a
	// real tester still can't fudge the prediction they're being graded against.
	PredictedScore *float64 `json:"predictedScore"`
	Hops           *int     `json:"hops"`
	CorrelatedHops *bool    `json:"correlatedHops"`
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
func (a *API) pathFeatures(tenant, pathID string) (score float64, hops int, correlated, found bool) {
	if a.analyzer == nil || pathID == "" {
		return 0, 0, false, false
	}
	for _, p := range a.analyzer.Latest(tenant) {
		if p.ID == pathID {
			return p.Score, len(p.Steps), p.CorrelatedHops, true
		}
	}
	return 0, 0, false, false
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
	// Capture the model's prediction and the path's structure at verdict time,
	// server-side (the tester can't fudge them), so this verdict becomes a calibration
	// data point that can also be segmented by structure. When the path isn't live
	// (a synthetic/offline verdict), fall back to client-supplied features.
	score, hops, correlated, found := a.pathFeatures(tenant, req.PathID)
	if !found {
		if req.PredictedScore != nil {
			score = *req.PredictedScore
		}
		if req.Hops != nil {
			hops = *req.Hops
		}
		if req.CorrelatedHops != nil {
			correlated = *req.CorrelatedHops
		}
	}
	rec, err := a.validation.Put(validation.Record{
		PathID:         req.PathID,
		Tenant:         tenant,
		Outcome:        validation.Outcome(req.Outcome),
		Source:         req.Source,
		Evidence:       req.Evidence,
		Route:          req.Route,
		PredictedScore: score,
		Hops:           hops,
		CorrelatedHops: correlated,
		Detected:       req.Detected,
	})
	if err != nil {
		switch {
		case errors.Is(err, validation.ErrInvalidOutcome),
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
