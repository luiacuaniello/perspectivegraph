package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
)

// authOn is an Authenticator that reports itself enabled without doing any real
// authentication: these tests exercise the handlers' ROLE checks, and the principal is
// injected directly into the context the way the auth middleware would.
type authOn struct{}

func (authOn) Enabled() bool { return true }
func (authOn) Authenticate(r *http.Request) (auth.Principal, bool) {
	return auth.PrincipalFromContext(r.Context()), true
}

func newAPI(t *testing.T, opts ...func(*API)) (*API, *suppress.Store) {
	t.Helper()
	m, err := graph.NewManager(context.Background(), func(context.Context, string) (graph.Store, error) {
		return memory.New(), nil
	})
	if err != nil {
		t.Fatalf("graph manager: %v", err)
	}
	st, err := suppress.New("")
	if err != nil {
		t.Fatalf("suppress store: %v", err)
	}
	a := New(m, analyzer.NewService(m, time.Second, nil), nil).WithSuppress(st)
	for _, o := range opts {
		o(a)
	}
	return a, st
}

// asRole issues a request carrying an authenticated principal of the given role.
func asRole(method, target, body string, role auth.Role) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	return r.WithContext(auth.WithPrincipal(r.Context(),
		auth.Principal{Subject: "tester", Role: role, Tenant: "acme"}))
}

func serve(t *testing.T, a *API, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := a.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// Suppressing a path takes it off the board - it is how a finding stops being reported.
// With auth on, that must be an admin-only act, or any read-only token could quietly
// hide the very attack paths the product exists to surface.
func TestSuppressionWritesRequireAdminWhenAuthIsOn(t *testing.T) {
	a, _ := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })

	body := `{"pathId":"p1","reason":"accept-risk","owner":"sec@acme.test"}`
	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{"create as viewer", asRole(http.MethodPost, "/suppressions", body, auth.RoleViewer)},
		{"delete as viewer", asRole(http.MethodDelete, "/suppressions/p1", "", auth.RoleViewer)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := serve(t, a, tc.req); rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403 - a viewer could hide findings", rec.Code)
			}
		})
	}
}

// Reading the board is not privileged: an analyst has to be able to see what was
// suppressed and by whom, which is the point of keeping the record at all.
func TestSuppressionListIsReadableByAViewer(t *testing.T) {
	a, _ := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })
	if rec := serve(t, a, asRole(http.MethodGet, "/suppressions", "", auth.RoleViewer)); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
}

func TestAdminCanSuppressAndUnsuppress(t *testing.T) {
	a, st := newAPI(t, func(a *API) { a.WithAuth(authOn{}, nil) })

	body := `{"pathId":"p1","reason":"accept-risk","owner":"sec@acme.test","note":"compensating control"}`
	rec := serve(t, a, asRole(http.MethodPost, "/suppressions", body, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status %d: %s", rec.Code, rec.Body)
	}
	if got := st.List("acme"); len(got) != 1 || got[0].PathID != "p1" {
		t.Fatalf("store holds %+v", got)
	}

	// 204: the un-suppression carries no body to return.
	if rec := serve(t, a, asRole(http.MethodDelete, "/suppressions/p1", "", auth.RoleAdmin)); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d: %s", rec.Code, rec.Body)
	}
	if got := st.List("acme"); len(got) != 0 {
		t.Fatalf("record survived the delete: %+v", got)
	}
}

// A suppression without a reason or an owner is an untraceable decision, so the store
// rejects it - and the handler has to pass that back as the caller's fault, with the
// reason, rather than a 500.
func TestInvalidSuppressionIs400WithTheReason(t *testing.T) {
	a, _ := newAPI(t)
	for _, tc := range []struct{ name, body string }{
		{"no reason", `{"pathId":"p1","owner":"sec@acme.test"}`},
		{"no owner", `{"pathId":"p1","reason":"accept-risk"}`},
		{"no path", `{"reason":"accept-risk","owner":"sec@acme.test"}`},
		{"unknown reason", `{"pathId":"p1","reason":"because-i-said-so","owner":"sec@acme.test"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/suppressions", strings.NewReader(tc.body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400 (body %s)", rec.Code, rec.Body)
			}
			if strings.TrimSpace(rec.Body.String()) == "" {
				t.Error("400 carried no reason for the caller to act on")
			}
		})
	}
}

func TestMalformedSuppressionBodyIs400(t *testing.T) {
	a, _ := newAPI(t)
	rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/suppressions", strings.NewReader(`{not json`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
}

// ttlDays is the ergonomic alternative to an RFC3339 timestamp; it has to produce a real
// expiry, or a "temporary" suppression silently becomes permanent.
func TestTTLDaysSetsAnExpiry(t *testing.T) {
	a, st := newAPI(t)
	body := `{"pathId":"p1","reason":"accept-risk","owner":"sec@acme.test","ttlDays":7}`
	if rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/suppressions", strings.NewReader(body))); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got := st.List("")
	if len(got) != 1 || got[0].ExpiresAt == nil {
		t.Fatalf("no expiry recorded: %+v", got)
	}
	if d := time.Until(*got[0].ExpiresAt); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Errorf("expiry is %v away, want about 7 days", d)
	}
}

// With auth off (the demo profile) the board stays usable without a principal, or
// `make demo` would not work out of the box.
func TestSuppressionWritesAreOpenWhenAuthIsOff(t *testing.T) {
	a, _ := newAPI(t)
	body := `{"pathId":"p1","reason":"accept-risk","owner":"sec@acme.test"}`
	if rec := serve(t, a, httptest.NewRequest(http.MethodPost, "/suppressions", strings.NewReader(body))); rec.Code != http.StatusOK {
		t.Fatalf("status %d with auth disabled: %s", rec.Code, rec.Body)
	}
}

func TestSuppressionListReportsPersistence(t *testing.T) {
	a, _ := newAPI(t)
	rec := serve(t, a, httptest.NewRequest(http.MethodGet, "/suppressions", nil))
	var got struct {
		Suppressions []any `json:"suppressions"`
		Persistent   bool  `json:"persistent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body)
	}
	if got.Persistent {
		t.Error("an in-memory store reported itself persistent, which would hide that decisions are lost on restart")
	}
}
