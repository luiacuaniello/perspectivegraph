package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
)

// ticketRequest is the POST /tickets body.
type ticketRequest struct {
	PathID string `json:"pathId"`
	Title  string `json:"title"`
	Owner  string `json:"owner"`
	Route  string `json:"route"`
}

// listTickets handles GET /tickets - the remediation work board for the tenant.
// Viewer is enough.
func (a *API) listTickets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"tickets":    a.ticket.List(tenantOf(r.Context())),
		"persistent": a.ticket.Persistent(),
		"dispatches": a.ticket.Dispatches(),
	})
}

// createTicket handles POST /tickets - open an owned remediation ticket for a
// path (idempotent per open path). Admin-only.
func (a *API) createTicket(w http.ResponseWriter, r *http.Request) {
	if !a.adminWritable(r) {
		writeJSONError(w, http.StatusForbidden, "admin role required to open tickets")
		return
	}
	var req ticketRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	tk, err := a.ticket.Create(r.Context(), ticket.Ticket{
		PathID: req.PathID,
		Tenant: tenantOf(r.Context()),
		Title:  req.Title,
		Owner:  req.Owner,
		Route:  req.Route,
	})
	if err != nil {
		switch {
		case errors.Is(err, ticket.ErrMissingPathID), errors.Is(err, ticket.ErrMissingOwner):
			writeJSONError(w, http.StatusBadRequest, err.Error())
		default:
			writeJSONError(w, http.StatusInternalServerError, "could not create ticket")
		}
		return
	}
	p := auth.PrincipalFromContext(r.Context())
	a.audit.Record("ticket.create", p.Subject, p.Role.String(), p.Tenant, map[string]any{
		"id": tk.ID, "path": tk.PathID, "owner": tk.Owner,
	})
	writeJSON(w, http.StatusOK, tk)
}

// closeTicket handles POST /tickets/{id}/close - mark the work done. Admin-only.
func (a *API) closeTicket(w http.ResponseWriter, r *http.Request) {
	if !a.adminWritable(r) {
		writeJSONError(w, http.StatusForbidden, "admin role required to close tickets")
		return
	}
	tk, err := a.ticket.Close(tenantOf(r.Context()), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ticket.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "ticket not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "could not close ticket")
		return
	}
	p := auth.PrincipalFromContext(r.Context())
	a.audit.Record("ticket.close", p.Subject, p.Role.String(), p.Tenant, map[string]any{
		"id": tk.ID, "path": tk.PathID,
	})
	writeJSON(w, http.StatusOK, tk)
}
