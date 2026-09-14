package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// The order is graded against the Priority the operator actually saw, so a tester must not
// be able to state it. For a live path the server captures it, exactly as it does S(P).
func TestVerdictCapturesTheLivePriorityNotTheClaimedOne(t *testing.T) {
	a, _ := testAPI(t)
	vs, err := validation.New("")
	if err != nil {
		t.Fatal(err)
	}
	a.WithValidation(vs)
	pathID := seedPRPath(t, a)

	var live float64
	for _, p := range a.analyzer.Latest(auth.DefaultTenant) {
		if p.ID == pathID {
			live = p.Priority
		}
	}
	const claimed = 3.0
	if live == claimed {
		t.Fatalf("the seeded path's live priority is %v - pick a different claimed value", live)
	}

	body := `{"pathId":"` + pathID + `","outcome":"confirmed","source":"red-team","predictedPriority":3}`
	rec := httptest.NewRecorder()
	a.putValidation(rec, httptest.NewRequest(http.MethodPost, "/validations", strings.NewReader(body)))
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	got, ok, _ := vs.Get(context.Background(), auth.DefaultTenant, pathID)
	if !ok {
		t.Fatal("the verdict was not recorded")
	}
	if got.PredictedPriority == nil {
		t.Fatal("a verdict on a live path did not capture its Priority")
	}
	if *got.PredictedPriority != live {
		t.Fatalf("stored priority %v, live %v - the client's claimed %v won", *got.PredictedPriority, live, claimed)
	}
}

// A synthetic or offline verdict has no live path to read, so the supplied value is the
// only evidence there is; that is the one case the client value is used.
func TestOfflineVerdictUsesTheSuppliedPriority(t *testing.T) {
	a, _ := testAPI(t)
	supplied := 12.5
	r := a.buildRecord(context.Background(), verdictFields{
		pathID: "not-a-live-path", outcome: "refuted", source: "genverdicts", predictedPriority: &supplied,
	})
	if r.PredictedPriority == nil || *r.PredictedPriority != supplied {
		t.Fatalf("offline verdict priority %v, want the supplied %v", r.PredictedPriority, supplied)
	}

	r = a.buildRecord(context.Background(), verdictFields{pathID: "not-a-live-path", outcome: "refuted", source: "genverdicts"})
	if r.PredictedPriority != nil {
		t.Fatalf("no live path and nothing supplied, yet priority %v was recorded", *r.PredictedPriority)
	}
}

// An undefined AUC must reach a client as null, not 0 - 0 is a real and alarming value
// (a perfectly inverted order), and a dashboard reading it would report exactly that.
func TestDiscriminationResolvesWithNullAUCUntilDefined(t *testing.T) {
	a := seededAPI(t)
	data := query(t, a, `{ calibration { discrimination { hasData verdict auc aucLow aucHigh positives negatives } priorityDiscrimination { hasData } } }`)
	c, _ := data["calibration"].(map[string]any)
	d, _ := c["discrimination"].(map[string]any)
	if d == nil {
		t.Fatal("discrimination resolved to nothing - it is non-null by contract")
	}
	if d["hasData"] != false || d["verdict"] != "insufficient-data" {
		t.Errorf("discrimination %v with no verdicts", d)
	}
	for _, k := range []string{"auc", "aucLow", "aucHigh"} {
		if d[k] != nil {
			t.Errorf("%s = %v with no verdicts; an undefined AUC must be null, not a number", k, d[k])
		}
	}
	if c["priorityDiscrimination"] != nil {
		t.Errorf("priorityDiscrimination = %v with no captured priorities, want null", c["priorityDiscrimination"])
	}
}

func TestDiscriminationResolvesANumberOnceBothClassesExist(t *testing.T) {
	a := seededAPI(t)
	vs, err := validation.New("")
	if err != nil {
		t.Fatal(err)
	}
	a.WithValidation(vs)
	hi, lo := 80.0, 10.0
	for i, v := range []struct {
		o     validation.Outcome
		score float64
		pr    *float64
	}{
		{validation.Confirmed, 0.9, &hi}, {validation.Refuted, 0.2, &lo},
	} {
		if _, err := vs.Put(context.Background(), validation.Record{
			Tenant: auth.DefaultTenant, PathID: "p" + string(rune('a'+i)), Outcome: v.o, Source: "test",
			PredictedScore: v.score, PredictedPriority: v.pr,
		}); err != nil {
			t.Fatal(err)
		}
	}
	data := query(t, a, `{ calibration { discrimination { hasData auc verdict } priorityDiscrimination { hasData auc } } }`)
	c, _ := data["calibration"].(map[string]any)
	d, _ := c["discrimination"].(map[string]any)
	if d["hasData"] != true || d["auc"] != 1.0 {
		t.Errorf("score discrimination %v, want hasData and auc 1", d)
	}
	// One of each class: the number is shown, the judgement is withheld.
	if d["verdict"] != "insufficient-data" {
		t.Errorf("verdict %v from one confirmed and one refuted verdict", d["verdict"])
	}
	pd, _ := c["priorityDiscrimination"].(map[string]any)
	if pd == nil || pd["auc"] != 1.0 {
		t.Errorf("priority discrimination %v, want auc 1", pd)
	}
}
