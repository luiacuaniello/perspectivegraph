package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sampleDrift() DriftEvent {
	return DriftEvent{
		Tenant: "acme",
		Appeared: []PathSummary{
			{ID: "ap-1", Route: "edge-alb → payments → admin", Score: 0.62, RuntimeConfirmed: true, KEV: true},
		},
		Resolved: []PathSummary{{ID: "ap-2", Route: "old → path", Score: 0.3}},
	}
}

func TestWebhookSlackFormat(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := New(srv.URL, "slack").Notify(context.Background(), sampleDrift()); err != nil {
		t.Fatal(err)
	}
	text, _ := got["text"].(string)
	for _, want := range []string{"1 new critical", "edge-alb → payments → admin", "62%", "⚡runtime", "🔥KEV", "1 path resolved"} {
		if !strings.Contains(text, want) {
			t.Errorf("slack text missing %q; got:\n%s", want, text)
		}
	}
}

func TestWebhookGenericFormat(t *testing.T) {
	var got DriftEvent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := New(srv.URL, "generic").Notify(context.Background(), sampleDrift()); err != nil {
		t.Fatal(err)
	}
	if got.Tenant != "acme" || len(got.Appeared) != 1 || got.Appeared[0].ID != "ap-1" {
		t.Errorf("generic payload not the raw DriftEvent: %+v", got)
	}
}

func TestEmptyAndNoop(t *testing.T) {
	// empty drift never posts
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("empty drift must not post")
	}))
	defer srv.Close()
	if err := New(srv.URL, "slack").Notify(context.Background(), DriftEvent{}); err != nil {
		t.Fatal(err)
	}
	if New("", "").Enabled() {
		t.Error("no URL → Noop, must be disabled")
	}
}
