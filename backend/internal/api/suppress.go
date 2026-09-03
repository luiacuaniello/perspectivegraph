package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
)

// suppressRequest is the POST /suppressions body. Either expiresAt (RFC3339) or
// ttlDays may set the expiry; ttlDays is the convenience the UI uses.
type suppressRequest struct {
	PathID    string `json:"pathId"`
	Reason    string `json:"reason"`
	Owner     string `json:"owner"`
	Note      string `json:"note"`
	ExpiresAt string `json:"expiresAt"` // RFC3339; empty = no expiry
	TTLDays   int    `json:"ttlDays"`   // alternative to expiresAt
}

// adminWritable reports whether the caller may perform an admin write (suppress,
// ticket, …). Writes are admin-only, but only when auth is enabled - in open/dev
// mode there is no RBAC, matching how the rest of the API behaves unauthenticated.
func (a *API) adminWritable(r *http.Request) bool {
	if !a.authEnabled() {
		return true
	}
	return auth.PrincipalFromContext(r.Context()).Role >= auth.RoleAdmin
}

// listSuppressions handles GET /suppressions - the triage board for the tenant
// (includes expired entries so lapsed decisions stay visible). Viewer is enough.
func (a *API) listSuppressions(w http.ResponseWriter, r *http.Request) {
	list, err := a.suppress.List(r.Context(), tenantOf(r.Context()))
	if err != nil {
		// Saying the store is unreachable beats returning an empty board: an analyst
		// would read that as "nothing is suppressed" and re-triage decisions they
		// already made.
		slog.Error("suppression store read failed", "err", err)
		writeJSONError(w, http.StatusServiceUnavailable, "suppression store unreachable - see the server log")
		return
	}
	if ids := a.scopedPathIDs(r.Context()); ids != nil {
		kept := make([]suppress.Record, 0, len(list))
		for _, rec := range list {
			if ids[rec.PathID] {
				kept = append(kept, rec)
			}
		}
		list = kept
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"suppressions": list,
		"persistent":   a.suppress.Persistent(),
	})
}

// putSuppression handles POST /suppressions - record or replace a triage decision
// for one attack path. Admin-only.
func (a *API) putSuppression(w http.ResponseWriter, r *http.Request) {
	if !a.adminWritable(r) {
		writeJSONError(w, http.StatusForbidden, "admin role required to suppress paths")
		return
	}
	var req suppressRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Suppressing hides a path from the board. An app-scoped admin hiding another
	// team's finding is the sharp end of this endpoint, so the path has to be one the
	// caller can see.
	if !a.mayActOnPath(r.Context(), req.PathID) {
		writeJSONError(w, http.StatusNotFound, "attack path not found (or out of your scope)")
		return
	}

	rec := suppress.Record{
		PathID: req.PathID,
		Tenant: tenantOf(r.Context()),
		Reason: suppress.Reason(req.Reason),
		Owner:  req.Owner,
		Note:   req.Note,
	}
	switch {
	case req.ExpiresAt != "":
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "expiresAt must be RFC3339")
			return
		}
		rec.ExpiresAt = &t
	case req.TTLDays > 0:
		t := time.Now().UTC().AddDate(0, 0, req.TTLDays)
		rec.ExpiresAt = &t
	}

	stored, err := a.suppress.Put(r.Context(), rec)
	if err != nil {
		// Validation failures (bad reason, missing owner/path) are client errors.
		switch {
		case errors.Is(err, suppress.ErrInvalidReason),
			errors.Is(err, suppress.ErrMissingOwner),
			errors.Is(err, suppress.ErrMissingPathID):
			writeJSONError(w, http.StatusBadRequest, err.Error())
		default:
			writeJSONError(w, http.StatusInternalServerError, "could not persist suppression")
		}
		return
	}
	p := auth.PrincipalFromContext(r.Context())
	a.audit.Record(r.Context(), "suppress.put", p.Subject, p.Role.String(), p.Tenant, map[string]any{
		"path": stored.PathID, "reason": string(stored.Reason), "owner": stored.Owner,
	})
	writeJSON(w, http.StatusOK, stored)
}

// deleteSuppression handles DELETE /suppressions/{pathID} - un-suppress a path,
// returning it to the active board. Admin-only.
func (a *API) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	if !a.adminWritable(r) {
		writeJSONError(w, http.StatusForbidden, "admin role required to un-suppress paths")
		return
	}
	pathID := r.PathValue("pathID")
	if pathID == "" {
		writeJSONError(w, http.StatusBadRequest, "path id required")
		return
	}
	if !a.mayActOnPath(r.Context(), pathID) {
		writeJSONError(w, http.StatusNotFound, "attack path not found (or out of your scope)")
		return
	}
	if err := a.suppress.Delete(r.Context(), tenantOf(r.Context()), pathID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "could not delete suppression")
		return
	}
	p := auth.PrincipalFromContext(r.Context())
	a.audit.Record(r.Context(), "suppress.delete", p.Subject, p.Role.String(), p.Tenant, map[string]any{
		"path": pathID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
