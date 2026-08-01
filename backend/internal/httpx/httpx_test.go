package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDoDecodesASuccessfulResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "payments", "hops": 5})
	}))
	defer srv.Close()

	var out struct {
		Name string `json:"name"`
		Hops int    `json:"hops"`
	}
	if err := Do(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, "", nil, &out); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if out.Name != "payments" || out.Hops != 5 {
		t.Fatalf("decoded %+v", out)
	}
}

func TestDoSendsBodyHeadersAndContentType(t *testing.T) {
	var (
		gotBody, gotAuth, gotCT, gotMethod string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody, gotAuth, gotCT, gotMethod = string(b), r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Method
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	err := Do(context.Background(), srv.Client(), http.MethodPost, srv.URL,
		map[string]string{"Authorization": "Bearer t"}, "application/json", []byte(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotMethod != http.MethodPost || gotBody != `{"a":1}` {
		t.Errorf("method=%q body=%q", gotMethod, gotBody)
	}
	if gotAuth != "Bearer t" || gotCT != "application/json" {
		t.Errorf("auth=%q content-type=%q", gotAuth, gotCT)
	}
}

// A 2xx with no out is a valid "fire and forget" call - webhooks and status posts use
// it - and must not be turned into an error by trying to decode an empty body.
func TestDoAcceptsSuccessWithNoDecodeTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	if err := Do(context.Background(), srv.Client(), http.MethodPost, srv.URL, nil, "", nil, nil); err != nil {
		t.Fatalf("204 with no out returned %v", err)
	}
}

// A failed call must say what the server actually complained about; an opaque status
// turns a fixable misconfiguration (bad token, wrong project) into a support ticket.
func TestDoSurfacesTheServersErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("token lacks repo scope"))
	}))
	defer srv.Close()

	err := Do(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, "", nil, nil)
	if err == nil {
		t.Fatal("a 403 returned no error")
	}
	if !strings.Contains(err.Error(), "token lacks repo scope") {
		t.Errorf("error %q does not carry the server's message", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q does not carry the status", err)
	}
}

// The error body is read under a cap, so a server that answers an error with megabytes
// cannot be used to blow up the caller's memory.
func TestDoCapsTheErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("x", 64<<10)))
	}))
	defer srv.Close()

	err := Do(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, "", nil, nil)
	if err == nil {
		t.Fatal("no error")
	}
	if len(err.Error()) > 8<<10 {
		t.Errorf("error message is %d bytes: the body cap is not being applied", len(err.Error()))
	}
}

func TestDoHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := Do(ctx, srv.Client(), http.MethodGet, srv.URL, nil, "", nil, nil); err == nil {
		t.Fatal("a cancelled context returned no error")
	}
}

func TestDoRejectsAnUnusableURL(t *testing.T) {
	if err := Do(context.Background(), http.DefaultClient, "GET", "://not a url", nil, "", nil, nil); err == nil {
		t.Fatal("a malformed URL returned no error")
	}
}
