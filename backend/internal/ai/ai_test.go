package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNopDisabled(t *testing.T) {
	c := New(Config{})
	if c.Enabled() {
		t.Fatal("client with no API key should be disabled")
	}
	if _, err := c.Complete(context.Background(), "s", "u"); err == nil {
		t.Error("disabled client should error on Complete")
	}
}

// TestComplete drives the real HTTP path against a fake Anthropic endpoint:
// it asserts the request shape (model, headers, message) and that text blocks
// are concatenated while thinking blocks are ignored.
func TestComplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "test-key" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("missing auth/version headers: %v", r.Header)
		}
		var req request
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Model != "claude-opus-4-8" || len(req.Messages) != 1 || req.Messages[0].Content != "hello" {
			t.Errorf("unexpected request body: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"content":[{"type":"thinking","text":""},{"type":"text","text":"the answer"}],"stop_reason":"end_turn"}`)
	}))
	defer srv.Close()

	c := New(Config{APIKey: "test-key", BaseURL: srv.URL})
	if !c.Enabled() {
		t.Fatal("client with a key should be enabled")
	}
	got, err := c.Complete(context.Background(), "you are helpful", "hello")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got != "the answer" {
		t.Errorf("got %q, want %q", got, "the answer")
	}
}

func TestRefusalIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"content":[],"stop_reason":"refusal"}`)
	}))
	defer srv.Close()

	c := New(Config{APIKey: "k", BaseURL: srv.URL})
	if _, err := c.Complete(context.Background(), "", "x"); err == nil || !strings.Contains(err.Error(), "declined") {
		t.Errorf("a refusal should surface as a 'declined' error, got %v", err)
	}
}

// TestHuggingFaceComplete drives the OpenAI-compatible path against a fake HF
// router: it asserts the chat-completions request shape (bearer token, model,
// system+user messages) and that the assistant message text is returned.
func TestHuggingFaceComplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer hf-test-token" {
			t.Errorf("missing/bad bearer auth: %q", r.Header.Get("Authorization"))
		}
		var req chatRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Model != "test-model" || len(req.Messages) != 2 ||
			req.Messages[0].Role != "system" || req.Messages[1].Role != "user" || req.Messages[1].Content != "hello" {
			t.Errorf("unexpected request body: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"the answer"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	// No Anthropic key → the HF (OpenAI-compatible) client is selected.
	c := New(Config{HFToken: "hf-test-token", HFModel: "test-model", HFBaseURL: srv.URL})
	if !c.Enabled() {
		t.Fatal("client with an HF token should be enabled")
	}
	got, err := c.Complete(context.Background(), "you are helpful", "hello")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got != "the answer" {
		t.Errorf("got %q, want %q", got, "the answer")
	}
}

// TestProviderSelection pins the credential precedence: Anthropic wins when both
// are set; HF is used when only its token is present; neither → disabled Nop.
func TestProviderSelection(t *testing.T) {
	cases := []struct {
		name         string
		cfg          Config
		wantProvider string
		wantEnabled  bool
	}{
		{"anthropic only", Config{APIKey: "a"}, "anthropic", true},
		{"hf only", Config{HFToken: "h"}, "huggingface", true},
		{"both → anthropic wins", Config{APIKey: "a", HFToken: "h"}, "anthropic", true},
		{"neither", Config{}, "none", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := New(tc.cfg).Enabled(); got != tc.wantEnabled {
				t.Errorf("Enabled() = %v, want %v", got, tc.wantEnabled)
			}
			if p, _ := Provider(tc.cfg); p != tc.wantProvider {
				t.Errorf("Provider() = %q, want %q", p, tc.wantProvider)
			}
		})
	}
}
