package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
// It spoke plain HTTP, so turning TLS on marked a working backend unhealthy. And it must
// verify what answers: the process's own certificate is the only root it trusts, so
// another server on that port - with a certificate for the same name - is refused.
func TestHealthCheckSpeaksTLSAndVerifiesItsOwnCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	dir := t.TempDir()
	writePEM := func(name string, der []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Setenv("API_ADDR", strings.TrimPrefix(srv.URL, "https://"))
	t.Setenv("TLS_KEY_FILE", filepath.Join(dir, "unused.key"))

	t.Setenv("TLS_CERT_FILE", writePEM("own.crt", srv.Certificate().Raw))
	if err := healthCheck(); err != nil {
		t.Fatalf("probe against its own certificate: %v", err)
	}

	// A stranger's certificate for the same names: whoever answers must hold OUR key.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), DNSNames: srv.Certificate().DNSNames,
		IPAddresses: srv.Certificate().IPAddresses, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	other, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TLS_CERT_FILE", writePEM("other.crt", other))
	if err := healthCheck(); err == nil {
		t.Error("the probe trusted a server that does not hold the configured certificate")
	}

	t.Setenv("TLS_CERT_FILE", "")
	if err := healthCheck(); err == nil {
		t.Error("a plain-HTTP probe of an HTTPS listener reported healthy")
	}
}
