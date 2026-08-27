package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/config"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// runVerifyAudit re-walks the tamper-evident audit chain and reports how many records
// held, failing at the first one that does not.
//
// The chain lives in one of two places, and the check has to follow it there. Under
// GOVERNANCE_BACKEND=postgres the backend writes the chain to the database instead of to
// AUDIT_LOG_PATH - that is what lets replicas exceed 1 - and a file-only verifier left
// exactly that deployment with no way to run the check the threat model names as its
// non-repudiation control. The control existed; the way to exercise it did not.
//
// The database is addressed through the environment (POSTGRES_DSN, or the discrete
// POSTGRES_* keys, read exactly as the server reads them, `_FILE` variants included)
// rather than through a flag, because a DSN carries a password and an argument is
// visible to every process on the host.
func runVerifyAudit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	postgres := fs.Bool("postgres", false,
		"verify the chain in the governance database (addressed by POSTGRES_DSN / POSTGRES_*) instead of in a file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sealer, err := cryptostore.New(os.Getenv("STORE_ENCRYPTION_KEY"))
	if err != nil {
		return fmt.Errorf("verify-audit: %w", err)
	}

	var (
		records int
		invalid error
		note    string // what retention has removed, printed under the result
	)
	if *postgres {
		db, derr := openGovernanceDB()
		if derr != nil {
			return derr
		}
		defer func() { _ = db.Close() }()
		// A whole chain, one row at a time, over a network: generous but bounded, so a
		// wedged connection ends as an error rather than a command that never returns.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		records, invalid = audit.VerifyPG(ctx, db, audit.WithSealer(sealer))
		// Say what the verification actually covered. "N records verified" reads as "the
		// whole log", and under a retention policy it is not - the operator should learn
		// that here rather than from a compliance question later.
		if cp, pruned, cerr := audit.ReadCheckpointPG(ctx, db); cerr == nil && pruned {
			note = fmt.Sprintf(
				"retention: %d older record(s) pruned through seq %d, last on %s - verified from seq %d\n",
				cp.PrunedRecords, cp.PrunedThroughSeq, cp.PrunedAt.UTC().Format(time.RFC3339),
				cp.PrunedThroughSeq+1)
		}
	} else {
		if fs.NArg() == 0 {
			return errors.New("verify-audit: need a log file path, or -postgres to read the chain from the governance database")
		}
		records, invalid = audit.Verify(fs.Arg(0), audit.WithSealer(sealer))
	}
	if invalid != nil {
		return fmt.Errorf("audit chain INVALID after %d records: %w", records, invalid)
	}

	fmt.Fprintf(out, "audit chain OK: %d records verified\n", records)
	if note != "" {
		fmt.Fprint(out, note)
	}
	return nil
}

// openGovernanceDB connects to the database the governance stores use, and refuses early
// if the audit chain is not in it.
//
// Without that check, a DSN pointing at the wrong database - or at one the backend has
// never run against - surfaces as a query failure from the verifier, which the caller
// would then report as "audit chain INVALID". Telling an operator their audit log has
// been tampered with because they mistyped a database name is the one wrong answer this
// command must never give.
func openGovernanceDB() (*sql.DB, error) {
	db, err := sql.Open("postgres", config.Load().PostgresDSN)
	if err != nil {
		return nil, fmt.Errorf("verify-audit: open the governance database: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("verify-audit: reach the governance database: %w", err)
	}

	var table sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('audit_log')::text`).Scan(&table); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("verify-audit: look for the audit chain: %w", err)
	}
	if !table.Valid {
		_ = db.Close()
		return nil, errors.New("verify-audit: this database has no audit_log table - check POSTGRES_DSN, or the backend has never run against it with GOVERNANCE_BACKEND=postgres")
	}
	return db, nil
}
