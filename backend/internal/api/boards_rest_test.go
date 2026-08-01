package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// withBoards attaches in-memory ticket and validation stores to an API under test.
func withBoards(t *testing.T, a *API) (*ticket.Store, *validation.Store) {
	t.Helper()
	tk, err := ticket.New("", "")
	if err != nil {
		t.Fatalf("ticket store: %v", err)
	}
	vs, err := validation.New("")
	if err != nil {
		t.Fatalf("validation store: %v", err)
	}
	a.WithTickets(tk).WithValidation(vs)
	return tk, vs
}

// ── tickets ─────────────────────────────────────────────────────────────────

// A ticket is the closed-loop half of the product: it asserts someone owns a path and
// will fix it. Opening or closing one under a read-only token would let anyone declare
// work done, so with auth on both are admin-only.
func TestTicketWritesRequireAdminWhenAuthIsOn(t *testing.T) {
	a, _ := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })
	withBoards(t, a)

	body := `{"pathId":"p1","title":"cut edge-alb → payments-admin","owner":"sec@acme.test"}`
	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{"create as viewer", asRole(http.MethodPost, "/tickets", body, auth.RoleViewer)},
		{"close as viewer", asRole(http.MethodPost, "/tickets/t1/close", "", auth.RoleViewer)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := serve(t, a, tc.req); rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403", rec.Code)
			}
		})
	}
}

func TestTicketListIsReadableByAViewer(t *testing.T) {
	a, _ := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })
	withBoards(t, a)
	if rec := serve(t, a, asRole(http.MethodGet, "/tickets", "", auth.RoleViewer)); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
}

func TestAdminCanOpenAndCloseATicket(t *testing.T) {
	a, _ := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })
	tk, _ := withBoards(t, a)

	body := `{"pathId":"p1","title":"cut the route","owner":"sec@acme.test","route":"edge-alb → payments-admin"}`
	rec := serve(t, a, asRole(http.MethodPost, "/tickets", body, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		ID     string `json:"id"`
		PathID string `json:"path_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response is not JSON: %v (%s)", err, rec.Body)
	}
	if created.ID == "" {
		t.Fatalf("no ticket id returned, so the caller cannot close it later: %s", rec.Body)
	}
	if got := tk.List("acme"); len(got) != 1 {
		t.Fatalf("store holds %d tickets, want 1", len(got))
	}

	if rec := serve(t, a, asRole(http.MethodPost, "/tickets/"+created.ID+"/close", "", auth.RoleAdmin)); rec.Code != http.StatusOK {
		t.Fatalf("close: status %d: %s", rec.Code, rec.Body)
	}
}

// Closing something that does not exist is the caller's mistake, and must be
// distinguishable from a server fault or they will retry forever.
func TestClosingAnUnknownTicketIs404(t *testing.T) {
	a, _ := newAPI(t)
	withBoards(t, a)
	rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/tickets/does-not-exist/close", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404: %s", rec.Code, rec.Body)
	}
}

// A ticket with no path or no owner is not accountable work, so the store refuses it
// and the handler has to report that as a 400 carrying the reason.
func TestInvalidTicketIs400WithTheReason(t *testing.T) {
	a, _ := newAPI(t)
	withBoards(t, a)
	for _, tc := range []struct{ name, body string }{
		{"no path", `{"title":"x","owner":"sec@acme.test"}`},
		{"no owner", `{"pathId":"p1","title":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/tickets", strings.NewReader(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), "ticket:") {
				t.Errorf("400 does not carry the store's reason: %s", rec.Body)
			}
		})
	}
}

func TestMalformedTicketBodyIs400(t *testing.T) {
	a, _ := newAPI(t)
	withBoards(t, a)
	rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/tickets", strings.NewReader(`{oops`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

// ── validations ─────────────────────────────────────────────────────────────

// Verdicts are what the whole calibration report is computed from. If a read-only token
// could file them, anyone could make the engine look as well-calibrated as they liked -
// which would quietly destroy the one number the product asks to be judged on.
func TestValidationWritesRequireAdminWhenAuthIsOn(t *testing.T) {
	a, _ := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })
	withBoards(t, a)

	body := `{"pathId":"p1","outcome":"confirmed","source":"caldera"}`
	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{"record as viewer", asRole(http.MethodPost, "/validations", body, auth.RoleViewer)},
		{"delete as viewer", asRole(http.MethodDelete, "/validations/v1", "", auth.RoleViewer)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := serve(t, a, tc.req); rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403 - a viewer could forge the calibration dataset", rec.Code)
			}
		})
	}
}

func TestAdminCanRecordAndDeleteAValidation(t *testing.T) {
	a, _ := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })
	_, vs := withBoards(t, a)

	body := `{"pathId":"p1","outcome":"confirmed","source":"caldera","predictedScore":0.55}`
	rec := serve(t, a, asRole(http.MethodPost, "/validations", body, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("record: status %d: %s", rec.Code, rec.Body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("no verdict id returned: %v (%s)", err, rec.Body)
	}
	if got := vs.List("acme"); len(got) != 1 {
		t.Fatalf("store holds %d verdicts, want 1", len(got))
	}

	rec = serve(t, a, asRole(http.MethodDelete, "/validations/"+created.ID, "", auth.RoleAdmin))
	if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d: %s", rec.Code, rec.Body)
	}
	if got := vs.List("acme"); len(got) != 0 {
		t.Fatalf("verdict survived the delete: %+v", got)
	}
}

// The store's vocabulary is closed on purpose - an outcome or scope it does not know
// would silently land in the wrong calibration track, or in none at all.
func TestInvalidVerdictIs400WithTheReason(t *testing.T) {
	a, _ := newAPI(t)
	withBoards(t, a)
	for _, tc := range []struct{ name, body string }{
		{"unknown outcome", `{"pathId":"p1","outcome":"probably","source":"caldera"}`},
		{"unknown scope", `{"pathId":"p1","outcome":"confirmed","scope":"galaxy","source":"caldera"}`},
		{"no source", `{"pathId":"p1","outcome":"confirmed"}`},
		{"no path", `{"outcome":"confirmed","source":"caldera"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/validations", strings.NewReader(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), "validation:") {
				t.Errorf("400 does not carry the store's reason: %s", rec.Body)
			}
		})
	}
}

// The scopes exist so that verdicts about different events are graded separately; all
// three have to be accepted over the wire or a whole track is unreachable by API.
func TestEveryScopeIsAcceptedOverTheWire(t *testing.T) {
	a, _ := newAPI(t)
	_, vs := withBoards(t, a)
	for _, scope := range []string{"path", "target", "edge"} {
		body := `{"pathId":"p-` + scope + `","outcome":"confirmed","scope":"` + scope + `","source":"harness","predictedScore":0.4}`
		rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/validations", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Errorf("scope %q rejected with %d: %s", scope, rec.Code, rec.Body)
		}
	}
	if got := vs.List(""); len(got) != 3 {
		t.Errorf("stored %d verdicts, want one per scope", len(got))
	}
}

func TestMalformedVerdictBodyIs400(t *testing.T) {
	a, _ := newAPI(t)
	withBoards(t, a)
	rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/validations", strings.NewReader(`{`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

func TestValidationListIsReadableByAViewer(t *testing.T) {
	a, _ := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })
	withBoards(t, a)
	if rec := serve(t, a, asRole(http.MethodGet, "/validations", "", auth.RoleViewer)); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
}
