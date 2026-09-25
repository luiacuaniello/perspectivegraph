package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A listener that cannot bind must stop the process. It used to log one line while the
// process kept running without that port, and a probe on the port that did bind saw a
// healthy replica.
func TestServeHTTPFailsTheProcessWhenItCannotBind(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed := make(chan error, 1)
	var wg sync.WaitGroup
	serveHTTP(ctx, &wg, func(err error) { failed <- err }, "ingestion",
		&http.Server{Addr: taken.Addr().String(), ReadHeaderTimeout: time.Second}, "", "")

	select {
	case err := <-failed:
		if !strings.Contains(err.Error(), "ingestion listener on "+taken.Addr().String()) {
			t.Errorf("error %q does not say which listener failed and where", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a listener that could not bind did not report it")
	}
	cancel()
	wg.Wait()
}

// A server shut down on purpose is not a failure.
func TestServeHTTPShutdownIsNotAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls []error
	var mu sync.Mutex
	var wg sync.WaitGroup
	serveHTTP(ctx, &wg, func(err error) { mu.Lock(); calls = append(calls, err); mu.Unlock() }, "api",
		&http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second}, "", "")
	time.Sleep(200 * time.Millisecond)
	cancel()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	for _, err := range calls {
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("a graceful shutdown was reported as a failure: %v", err)
		}
	}
}

// With in-app TLS on, the container's health probe must speak HTTPS to its own listener.
// It spoke plain HTTP, so turning TLS on marked a working backend unhealthy.
func TestHealthCheckSpeaksTLSWhenTheAPIDoes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("API_ADDR", strings.TrimPrefix(srv.URL, "https://"))
	t.Setenv("TLS_CERT_FILE", "/etc/pg/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/pg/tls.key")
	if err := healthCheck(); err != nil {
		t.Fatalf("health probe against an HTTPS API: %v", err)
	}
	t.Setenv("TLS_CERT_FILE", "")
	if err := healthCheck(); err == nil {
		t.Error("a plain-HTTP probe of an HTTPS listener reported healthy")
	}
}
