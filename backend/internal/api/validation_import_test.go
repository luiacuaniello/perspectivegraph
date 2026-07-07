package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// A BAS report posted to /validations/import is matched to live paths server-side:
// a finding referencing a crown-jewel target is recorded against the matching path
// (target-scoped ⇒ carries the per-target compromise probability), and a finding
// that matches nothing is reported as unmatched, not recorded.
func TestImportValidationsMatchesAndCounts(t *testing.T) {
	a, _ := testAPI(t)
	vs, err := validation.New("")
	if err != nil {
		t.Fatal(err)
	}
	a.WithValidation(vs)
	pathID := seedPRPath(t, a) // entry "alb" → crown jewel "admin"

	body := `{"source":"safebreach","findings":[
	  {"target":"admin","from":"alb","outcome":"confirmed","scope":"target","evidence":"reached the jewel"},
	  {"target":"does-not-exist","outcome":"confirmed","evidence":"no live path"}
	]}`
	rec := httptest.NewRecorder()
	a.importValidations(rec, httptest.NewRequest(http.MethodPost, "/validations/import", strings.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct{ Recorded, Unmatched int }
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Recorded != 1 || resp.Unmatched != 1 {
		t.Errorf("recorded=%d unmatched=%d, want 1/1", resp.Recorded, resp.Unmatched)
	}

	got, ok := vs.Get(auth.DefaultTenant, pathID)
	if !ok {
		t.Fatal("the matched finding was not recorded against the live path")
	}
	if got.Scope != validation.ScopeTarget {
		t.Errorf("scope = %q, want target", got.Scope)
	}
	if got.Source != "safebreach" {
		t.Errorf("source = %q, want the report source safebreach", got.Source)
	}
	if got.PredictedCompromise <= 0 {
		t.Errorf("a target-scoped verdict should carry a captured per-target compromise probability, got %v", got.PredictedCompromise)
	}
}
