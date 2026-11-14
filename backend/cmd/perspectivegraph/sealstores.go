package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/config"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// plaintextFix is what a refused store tells the operator, once, at the top of the log.
const plaintextFix = "a store holds records STORE_ENCRYPTION_KEY did not seal. If they predate the key, " +
	"seal them once with the engine stopped: `perspectivegraph seal-stores` (-dry-run first lists what it " +
	"finds), or one start with STORE_SEAL_EXISTING=true (Helm: crypto.sealExisting). If they do not predate " +
	"it, someone wrote to the store without the key: compare it with a backup before sealing anything"

// runSealStores seals, once, what the governance stores and the audit log hold from before
// STORE_ENCRYPTION_KEY was set.
//
// With the key on, the engine refuses a record the key did not seal. It used to read one,
// so that the stores written before the key stayed readable, and that same rule let anyone
// who could write to a store's file add a record nobody sealed - a suppression hiding a
// path, or an audit chain rewritten in plaintext, which verifies because its hashes carry
// no key. What predates the key is sealed here instead, on purpose: with the engine
// stopped, and reported store by store. The stores are the ones the engine opens, from
// the same environment.
func runSealStores(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("seal-stores", flag.ContinueOnError)
	fs.SetOutput(out)
	dryRun := fs.Bool("dry-run", false, "list what each store holds in plaintext, and seal nothing")
	fs.Usage = func() {
		fmt.Fprintln(out, "usage: perspectivegraph seal-stores [-dry-run]")
		fmt.Fprintln(out, "Seals what the stores hold from before STORE_ENCRYPTION_KEY was set; run it with the engine stopped.")
		fmt.Fprintln(out, "The stores, the key and the backend come from the environment, as the server reads them.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("seal-stores takes no arguments - the stores come from the environment: %s", strings.Join(fs.Args(), " "))
	}

	cfg := config.Load()
	sealer, err := cryptostore.New(cfg.StoreEncryptionKey)
	if err != nil {
		return fmt.Errorf("seal-stores: %w", err)
	}
	var db *sql.DB
	if cfg.GovernanceBackend == "postgres" {
		if db, err = openGovernanceDB("seal-stores"); err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
	}
	// A whole audit chain, over a network: generous but bounded, as verify-audit is.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	return sealStores(ctx, cfg, sealer, db, *dryRun, out)
}

// sealExisting is STORE_SEAL_EXISTING: one start that seals what predates the key, before
// the stores open, for where seal-stores against a stopped engine is awkward - a
// Kubernetes pod. Every start it stays on seals whatever plaintext it finds, which is the
// acceptance it replaced, so each one says so.
func sealExisting(ctx context.Context, cfg config.Config, sealer cryptostore.Sealer, db *sql.DB) error {
	var found strings.Builder
	if err := sealStores(ctx, cfg, sealer, db, false, &found); err != nil {
		return fmt.Errorf("STORE_SEAL_EXISTING: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(found.String()), "\n") {
		slog.Warn("STORE_SEAL_EXISTING", "store", line)
	}
	slog.Warn("STORE_SEAL_EXISTING is on: turn it off now that this start has sealed the stores - " +
		"left on, every start seals whatever plaintext it finds, which is the acceptance it replaced")
	return nil
}

// sealStores seals what the stores the engine opens hold in plaintext, one line per store
// on out. With a governance database (db) that is the audit chain in it - the engine seals
// nothing else there - and otherwise every store kept on a file.
func sealStores(ctx context.Context, cfg config.Config, sealer cryptostore.Sealer, db *sql.DB, dryRun bool, out io.Writer) error {
	if !sealer.Enabled() {
		return errors.New("seal-stores: STORE_ENCRYPTION_KEY is empty, so there is no key to seal with")
	}
	sealed := "sealed"
	if dryRun {
		sealed = "would seal"
	}
	report := func(name, where string, r cryptostore.Report) {
		switch {
		case r.Absent:
			fmt.Fprintf(out, "%-12s %s: empty\n", name, where)
		case r.Plain == 0:
			fmt.Fprintf(out, "%-12s %s: already sealed (%d record(s))\n", name, where, r.Sealed)
		default:
			fmt.Fprintf(out, "%-12s %s: %s %d plaintext record(s); %d already sealed\n", name, where, sealed, r.Plain, r.Sealed)
		}
		if r.Torn > 0 {
			fmt.Fprintf(out, "%-12s %s: %d final record(s) torn by a crash, which the store drops when it loads\n", name, where, r.Torn)
		}
	}

	if db != nil {
		r, err := audit.SealPG(ctx, db, sealer, dryRun)
		if err != nil {
			return fmt.Errorf("audit chain (postgres): %w", err)
		}
		report("audit", "postgres", r)
		return nil
	}
	stores := []struct {
		name, path string
		seal       func(string, cryptostore.Sealer, bool) (cryptostore.Report, error)
	}{
		{"suppressions", cfg.SuppressionsPath, cryptostore.SealFile},
		{"tickets", cfg.TicketsPath, cryptostore.SealFile},
		{"validations", cfg.ValidationsPath, validation.SealFile},
		{"history", cfg.HistoryPath, cryptostore.SealFile},
		{"audit", cfg.AuditLogPath, audit.SealFile},
	}
	onFile := 0
	for _, st := range stores {
		if st.path == "" {
			continue
		}
		onFile++
		r, err := st.seal(st.path, sealer, dryRun)
		if err != nil {
			return fmt.Errorf("%s: %w", st.name, err)
		}
		report(st.name, st.path, r)
	}
	if onFile == 0 {
		fmt.Fprintln(out, "no store is kept on a file (no *_PATH is set): they are in memory, and there is nothing to seal")
	}
	return nil
}
