package api

import (
	"context"
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
