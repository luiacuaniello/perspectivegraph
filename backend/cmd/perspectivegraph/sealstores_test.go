package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/config"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// plaintextStores writes one store of each kind the way an engine running without
// STORE_ENCRYPTION_KEY writes them, and points the environment at them.
func plaintextStores(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	paths := map[string]string{
		"SUPPRESSIONS_PATH": filepath.Join(dir, "suppressions.json"),
		"TICKETS_PATH":      filepath.Join(dir, "tickets.json"),
		"VALIDATIONS_PATH":  filepath.Join(dir, "validations.json"),
		"HISTORY_PATH":      filepath.Join(dir, "history.json"),
		"AUDIT_LOG_PATH":    filepath.Join(dir, "audit.log"),
	}
	ctx := context.Background()

	sup, err := suppress.New(paths["SUPPRESSIONS_PATH"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sup.Put(ctx, suppress.Record{PathID: "ap-1", Tenant: "acme", Reason: suppress.ReasonAcceptRisk, Owner: "secops"}); err != nil {
		t.Fatal(err)
	}
	tix, err := ticket.New(paths["TICKETS_PATH"], "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tix.Create(ctx, ticket.Ticket{PathID: "ap-2", Tenant: "acme", Title: "close the bucket", Owner: "secops"}); err != nil {
		t.Fatal(err)
	}
	ver, err := validation.New(paths["VALIDATIONS_PATH"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Put(ctx, validation.Record{PathID: "ap-3", Outcome: validation.Missed, Source: "bas", Tenant: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths["HISTORY_PATH"], []byte(`{"paths":[],"posture":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(paths["AUDIT_LOG_PATH"])
	if err != nil {
		t.Fatal(err)
	}
	l.Record(ctx, "suppress.create", "tok", "admin", "acme", nil)
	_ = l.Close()

	for k, v := range paths {
		t.Setenv(k, v)
	}
	t.Setenv("GOVERNANCE_BACKEND", "file")
	return paths
}

// The stores of an engine that ran without a key are refused once the key is set - which
// is the fix - and seal-stores is the way through: it seals each of them once, and from
// then on they open with the key, holding what they held.
func TestSealStoresSealsWhatTheEngineWroteBeforeTheKey(t *testing.T) {
	paths := plaintextStores(t)
	key := strings.Repeat("ab", 32)
	t.Setenv("STORE_ENCRYPTION_KEY", key)
	sealer, err := cryptostore.New(key)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	refused := func() error {
		_, err := suppress.New(paths["SUPPRESSIONS_PATH"], suppress.WithSealer(sealer))
		return err
	}
	if err := refused(); !errors.Is(err, cryptostore.ErrPlaintext) {
		t.Fatalf("the engine opened a store written before the key: %v, want ErrPlaintext", err)
	}

	var out bytes.Buffer
	if err := runSealStores([]string{"-dry-run"}, &out); err != nil {
		t.Fatalf("dry run: %v\n%s", err, out.String())
	}
	if n := strings.Count(out.String(), ": would seal "); n != 5 {
		t.Fatalf("the dry run names %d store(s) to seal, want 5:\n%s", n, out.String())
	}
	if err := refused(); !errors.Is(err, cryptostore.ErrPlaintext) {
		t.Fatalf("a dry run sealed the suppressions: %v", err)
	}

	out.Reset()
	if err := runSealStores(nil, &out); err != nil {
		t.Fatalf("seal: %v\n%s", err, out.String())
	}
	if n := strings.Count(out.String(), ": sealed "); n != 5 {
		t.Fatalf("seal-stores reports %d store(s) sealed, want 5:\n%s", n, out.String())
	}

	// Each opens with the key, as the engine opens it, and holds what it held.
	sup, err := suppress.New(paths["SUPPRESSIONS_PATH"], suppress.WithSealer(sealer))
	if err != nil {
		t.Fatalf("suppressions: %v", err)
	}
	if got, _ := sup.List(ctx, "acme"); len(got) != 1 {
		t.Errorf("suppressions: %d record(s), want 1", len(got))
	}
	tix, err := ticket.New(paths["TICKETS_PATH"], "", ticket.WithSealer(sealer))
	if err != nil {
		t.Fatalf("tickets: %v", err)
	}
	if got, _ := tix.List(ctx, "acme"); len(got) != 1 {
		t.Errorf("tickets: %d record(s), want 1", len(got))
	}
	ver, err := validation.New(paths["VALIDATIONS_PATH"], validation.WithSealer(sealer))
	if err != nil {
		t.Fatalf("validations: %v", err)
	}
	if got, _ := ver.List(ctx, "acme"); len(got) != 1 {
		t.Errorf("validations: %d record(s), want 1", len(got))
	}
	if _, err := history.New(paths["HISTORY_PATH"], history.WithSealer(sealer)); err != nil {
		t.Errorf("history: %v", err)
	}
	if n, err := audit.Verify(paths["AUDIT_LOG_PATH"], audit.WithSealer(sealer)); err != nil || n != 1 {
		t.Errorf("audit: %d record(s), %v; want 1 verified with the key", n, err)
	}

	out.Reset()
	if err := runSealStores(nil, &out); err != nil {
		t.Fatalf("a second run: %v", err)
	}
	if n := strings.Count(out.String(), ": already sealed"); n != 5 {
		t.Errorf("a second run finds %d store(s) already sealed, want 5:\n%s", n, out.String())
	}
}

// STORE_SEAL_EXISTING runs the same sealing at startup, before the stores open: the stores
// it leaves open with the key, and without a key it stops the start rather than pass.
func TestSealExistingSealsBeforeTheStoresOpen(t *testing.T) {
	paths := plaintextStores(t)
	key := strings.Repeat("ab", 32)
	t.Setenv("STORE_ENCRYPTION_KEY", key)
	t.Setenv("STORE_SEAL_EXISTING", "true")
	cfg := config.Load()
	if !cfg.StoreSealExisting {
		t.Fatal("STORE_SEAL_EXISTING=true did not reach the config")
	}
	sealer, err := cryptostore.New(cfg.StoreEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealExisting(context.Background(), cfg, sealer, nil); err != nil {
		t.Fatalf("sealExisting: %v", err)
	}
	if _, err := suppress.New(paths["SUPPRESSIONS_PATH"], suppress.WithSealer(sealer)); err != nil {
		t.Errorf("the suppressions do not open with the key after sealExisting: %v", err)
	}
	if _, err := audit.Open(paths["AUDIT_LOG_PATH"], audit.WithSealer(sealer)); err != nil {
		t.Errorf("the audit log does not open with the key after sealExisting: %v", err)
	}
	if err := sealExisting(context.Background(), cfg, cryptostore.Nop(), nil); err == nil {
		t.Error("STORE_SEAL_EXISTING without a key let the start go on")
	}
}

func TestSealStoresNeedsAKeyAndTakesNoArguments(t *testing.T) {
	plaintextStores(t)
	t.Setenv("STORE_ENCRYPTION_KEY", "")
	if err := runSealStores(nil, io.Discard); err == nil {
		t.Error("seal-stores ran without a key")
	}
	t.Setenv("STORE_ENCRYPTION_KEY", strings.Repeat("ab", 32))
	if err := runSealStores([]string{"/data/suppressions.json"}, io.Discard); err == nil {
		t.Error("seal-stores took a path as an argument; the stores come from the environment")
	}
}
