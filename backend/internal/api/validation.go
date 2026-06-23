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
}

// listValidations handles GET /validations - the verdicts board plus the rolled-up
// precision/recall over the validated subset. Viewer is enough.
func (a *API) listValidations(w http.ResponseWriter, r *http.Request) {
	tenant := tenantOf(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"validations": a.validation.List(tenant),
		"metrics":     a.validation.Metrics(tenant),
		"persistent":  a.validation.Persistent(),
	})
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
	rec, err := a.validation.Put(validation.Record{
		PathID:   req.PathID,
		Tenant:   tenantOf(r.Context()),
		Outcome:  validation.Outcome(req.Outcome),
		Source:   req.Source,
		Evidence: req.Evidence,
		Route:    req.Route,
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
