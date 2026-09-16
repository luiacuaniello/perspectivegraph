package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Anonymous exists so an instance can be PUBLISHED read-only. Everything that keeps that
// from becoming a way in is here: the role it may hand out, and the refusal to answer for
// a request that carried a credential.
func TestAnonymousMayOnlyGrantViewer(t *testing.T) {
	for _, role := range []Role{RoleOperator, RoleAdmin} {
		if a, err := NewAnonymous(role); err == nil {
			t.Errorf("NewAnonymous(%s) was accepted (%+v): a role that can write must be tied to a credential", role, a)
		}
	}
	a, err := NewAnonymous(RoleViewer)
	if err != nil || !a.Enabled() {
		t.Fatalf("NewAnonymous(viewer) = %v, %v", a, err)
	}
}

// Unset must stay closed: the zero value is how every deployment that never heard of this
// setting behaves, and it must reject anonymous callers.
func TestAnonymousIsOffUnlessAskedFor(t *testing.T) {
	var off *Anonymous
	if off.Enabled() {
		t.Error("a nil Anonymous reports itself enabled; an unset API_ANONYMOUS_ROLE would open the API")
	}
	if _, ok := off.Authenticate(httptest.NewRequest(http.MethodGet, "/graphql", nil)); ok {
		t.Error("a nil Anonymous authenticated a request")
	}
	if got, ok := (Chain{off}).Authenticate(httptest.NewRequest(http.MethodGet, "/graphql", nil)); ok {
		t.Errorf("a chain holding only a disabled Anonymous authenticated: %+v", got)
	}
}

func TestAnonymousAnswersOnlyForARequestWithNoCredential(t *testing.T) {
	a, err := NewAnonymous(RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	p, ok := a.Authenticate(r)
	if !ok || p.Role != RoleViewer || p.Subject != "anonymous" || p.Tenant != DefaultTenant {
		t.Fatalf("no-credential request got %+v (ok=%v), want an anonymous viewer on the default tenant", p, ok)
	}

	// A token that fails must FAIL. If anonymous answered here, revoking a leaked token
	// would silently downgrade its holder to public read instead of locking them out,
	// and RequireRole would never see an attempt to count toward the lockout.
	withToken := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	withToken.Header.Set("Authorization", "Bearer wrong-or-expired")
	if p, ok := a.Authenticate(withToken); ok {
		t.Errorf("a request carrying a credential was authenticated as %+v; a bad token must not fall through to anonymous", p)
	}
}

// The chain is the real arrangement: tokens first, anonymous last.
func TestAChainWithAnonymousStillRejectsABadToken(t *testing.T) {
	anon, err := NewAnonymous(RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	chain := Chain{NewTokenStore("s3cr3t:admin"), anon}

	bad := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	bad.Header.Set("Authorization", "Bearer not-the-token")
	if p, ok := chain.Authenticate(bad); ok {
		t.Errorf("a wrong token authenticated as %+v", p)
	}
	good := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	good.Header.Set("Authorization", "Bearer s3cr3t")
	if p, ok := chain.Authenticate(good); !ok || p.Role != RoleAdmin {
		t.Errorf("the admin token got %+v (ok=%v); anonymous must not shadow a real credential", p, ok)
	}
	if p, ok := chain.Authenticate(httptest.NewRequest(http.MethodGet, "/graphql", nil)); !ok || p.Role != RoleViewer {
		t.Errorf("a credential-less request got %+v (ok=%v), want viewer", p, ok)
	}
}
