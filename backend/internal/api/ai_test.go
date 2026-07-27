package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeAI struct {
	enabled bool
	gotUser string
	gotSys  string
	calls   int
}

func (f *fakeAI) Enabled() bool { return f.enabled }

func (f *fakeAI) Describe() (string, string) { return "anthropic", "test-model" }
func (f *fakeAI) Complete(_ context.Context, system, user string) (string, error) {
	f.calls++
	f.gotSys, f.gotUser = system, user
	return "AI ANSWER", nil
}

func TestAIDisabledReturns503(t *testing.T) {
	a, _ := testAPI(t)
	a.WithAI(&fakeAI{enabled: false})
	rec := httptest.NewRecorder()
	a.handleAISummary(rec, httptest.NewRequest(http.MethodGet, "/ai/summary", nil).WithContext(viewerCtx()))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("disabled AI should be 503, got %d", rec.Code)
	}
}

func TestAISummary(t *testing.T) {
	a, _ := testAPI(t)
	fa := &fakeAI{enabled: true}
	a.WithAI(fa)
	rec := httptest.NewRecorder()
	a.handleAISummary(rec, httptest.NewRequest(http.MethodGet, "/ai/summary", nil).WithContext(viewerCtx()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if fa.calls != 1 || !strings.Contains(rec.Body.String(), "AI ANSWER") {
		t.Errorf("summary not produced from the model: calls=%d body=%s", fa.calls, rec.Body.String())
	}
	if !strings.Contains(fa.gotSys, "executive") {
		t.Errorf("system prompt should brief executives: %q", fa.gotSys)
	}
}

func TestAIQueryValidation(t *testing.T) {
	a, _ := testAPI(t)
	a.WithAI(&fakeAI{enabled: true})

	rec := httptest.NewRecorder()
	a.handleAIQuery(rec, httptest.NewRequest(http.MethodPost, "/ai/query", strings.NewReader(`{"question":""}`)).WithContext(viewerCtx()))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty question should be 400, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	a.handleAIQuery(rec, httptest.NewRequest(http.MethodPost, "/ai/query", strings.NewReader(`{"question":"what is most at risk?"}`)).WithContext(viewerCtx()))
	if rec.Code != http.StatusOK {
		t.Errorf("valid question should be 200, got %d", rec.Code)
	}
}

func TestAIExplain(t *testing.T) {
	a, _ := testAPI(t)
	fa := &fakeAI{enabled: true}
	a.WithAI(fa)

	// unknown path → 404
	rec := httptest.NewRecorder()
	a.handleAIExplain(rec, httptest.NewRequest(http.MethodPost, "/ai/explain", strings.NewReader(`{"pathId":"nope"}`)).WithContext(viewerCtx()))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path should be 404, got %d", rec.Code)
	}

	// real path → 200, model called with the kill chain
	pathID := seedPRPath(t, a)
	rec = httptest.NewRecorder()
	a.handleAIExplain(rec, httptest.NewRequest(http.MethodPost, "/ai/explain", strings.NewReader(`{"pathId":"`+pathID+`"}`)).WithContext(viewerCtx()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if fa.calls == 0 || !strings.Contains(fa.gotUser, "Attack path:") {
		t.Errorf("explain did not pass the path to the model: %q", fa.gotUser)
	}
}

// The MCP tool descriptions tell an agent the scores are expert estimates and to call
// get_score_trust before quoting one. The prose the AI layer writes goes to executives,
// who have no such recourse - so the same caveat has to reach the model here too. This
// fails if a fourth prompt is ever added without it.
func TestEveryAIPromptCarriesTheScoreCaveat(t *testing.T) {
	for _, prompt := range []string{
		aiSystem("You are a principal security analyst briefing executives."),
		aiSystem("You answer questions about an organization's attack-path graph."),
		aiSystem("You explain a single attack path to an engineer in plain English."),
	} {
		if !strings.Contains(prompt, "expert estimates") {
			t.Errorf("system prompt does not say the scores are estimates: %q", prompt)
		}
		if !strings.Contains(prompt, "Never state one as a measured fact") {
			t.Errorf("system prompt does not forbid stating a score as fact: %q", prompt)
		}
	}
}

// An answer has to name the model that wrote it. The two supported backends are not
// interchangeable - the free path can be a small model writing a risk briefing - and
// prose reads with the same authority either way, so the reader needs to know which one
// they are reading.
func TestAIAnswerNamesTheModelThatWroteIt(t *testing.T) {
	a, _ := testAPI(t)
	a.WithAI(&fakeAI{enabled: true})
	rec := httptest.NewRecorder()
	a.handleAISummary(rec, httptest.NewRequest(http.MethodGet, "/ai/summary", nil).WithContext(viewerCtx()))

	var got struct {
		Answer   string `json:"answer"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if got.Answer == "" {
		t.Fatal("no answer returned")
	}
	if got.Provider != "anthropic" || got.Model != "test-model" {
		t.Errorf("provider/model = %q/%q, want anthropic/test-model", got.Provider, got.Model)
	}
	if strings.Contains(rec.Body.String(), "test-key") {
		t.Error("the credential must never appear in the response")
	}
}
