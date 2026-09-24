package main

import (
	"context"
	"errors"
	"net"
	"net/http"
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
