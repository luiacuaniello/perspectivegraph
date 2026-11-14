package audit

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luiacuaniello/perspectivegraph/internal/atomicfile"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// SealFile seals the lines of an audit log written before STORE_ENCRYPTION_KEY was set.
//
// The chain runs over each record in plaintext, so sealing a line changes no hash. The log
// is walked first, the plaintext lines read with the rest, and sealing is refused if it
// does not verify: sealing a chain that is already broken would certify it. Then every
// plaintext line is replaced by its sealed form - atomically, owner-only - and the result
// has to verify with the key alone. dryRun stops after the walk.
func SealFile(path string, s cryptostore.Sealer, dryRun bool) (cryptostore.Report, error) {
	var rep cryptostore.Report
	if !s.Enabled() {
		return rep, errors.New("audit: no key to seal with")
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && info.Size() == 0) {
		return cryptostore.Report{Absent: true}, nil
	}
	if err != nil {
		return rep, err
	}

	migrating := func(line []byte) ([]byte, error) {
		if line[0] == '{' {
			rep.Plain++
			return line, nil
		}
		raw, err := base64.StdEncoding.DecodeString(string(line))
		if err != nil {
			return nil, fmt.Errorf("audit: undecodable line: %w", err)
		}
		if !cryptostore.IsSealed(raw) {
			return nil, errors.New("audit: a line that is neither sealed nor a record - not one this engine wrote")
		}
		rep.Sealed++
		return s.Open(raw)
	}
	if _, err := verifyFile(path, migrating); err != nil {
		return rep, fmt.Errorf("%s does not verify, and sealing it would certify it: %w", path, err)
	}
	if dryRun || rep.Plain == 0 {
		return rep, nil
	}
	if err := rewriteSealed(path, s); err != nil {
		return rep, fmt.Errorf("seal %s: %w", path, err)
	}
	if _, err := Verify(path, WithSealer(s)); err != nil {
		return rep, fmt.Errorf("%s was sealed, but does not verify with the key: %w", path, err)
	}
	return rep, nil
}

// rewriteSealed replaces the log with a copy in which every plaintext line is sealed,
// through a temporary file renamed over it, so that a crash leaves the old log or the new
// one and never half of each.
func rewriteSealed(path string, s cryptostore.Sealer) error {
	src, err := os.Open(path) // #nosec G304 -- operator-configured audit-log path, not attacker-controlled
	if err != nil {
		return err
	}
	defer src.Close()

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp") // 0600, like the log
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // nothing left to remove once it is renamed

	w := bufio.NewWriter(tmp)
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if line[0] == '{' {
			sealed, err := encodeLine(line, s)
			if err != nil {
				_ = tmp.Close()
				return err
			}
			line = sealed
		}
		// Two writes rather than append(line, '\n'): line is the scanner's own buffer.
		if _, err := w.Write(line); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := sc.Err(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return atomicfile.SyncDir(dir)
}

// SealPG seals the fields of the audit records written to the database before
// STORE_ENCRYPTION_KEY was set: the fields are what the database keeps sealed, the chain
// columns staying readable by design. As SealFile does, it walks the chain first, the
// plaintext fields read with the rest, and refuses to seal one that does not verify; the
// rows are sealed in one transaction, and the result has to verify with the key alone.
// dryRun stops after the walk.
func SealPG(ctx context.Context, db *sql.DB, s cryptostore.Sealer, dryRun bool) (cryptostore.Report, error) {
	var rep cryptostore.Report
	if !s.Enabled() {
		return rep, errors.New("audit: no key to seal with")
	}
	migrating := func(fields []byte) ([]byte, error) {
		if !sealedFields(fields) {
			rep.Plain++
			return fields, nil
		}
		rep.Sealed++
		return openFields(fields, s)
	}
	n, err := verifyPG(ctx, db, migrating)
	if err != nil {
		return rep, fmt.Errorf("the audit chain in the database does not verify, and sealing it would certify it: %w", err)
	}
	if n == 0 {
		return cryptostore.Report{Absent: true}, nil
	}
	if dryRun || rep.Plain == 0 {
		return rep, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return rep, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT seq, fields FROM audit_log ORDER BY seq`)
	if err != nil {
		return rep, err
	}
	type plaintext struct {
		seq    int64
		fields []byte
	}
	var todo []plaintext
	for rows.Next() {
		var p plaintext
		if err := rows.Scan(&p.seq, &p.fields); err != nil {
			_ = rows.Close()
			return rep, err
		}
		if !sealedFields(p.fields) {
			todo = append(todo, p)
		}
	}
	if err := rows.Close(); err != nil {
		return rep, err
	}
	for _, p := range todo {
		raw := p.fields
		if len(bytes.TrimSpace(raw)) == 0 {
			raw = []byte("null")
		}
		sealed, err := s.Seal(raw)
		if err != nil {
			return rep, err
		}
		wrapped, err := json.Marshal(base64.StdEncoding.EncodeToString(sealed))
		if err != nil {
			return rep, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE audit_log SET fields = $1 WHERE seq = $2`, wrapped, p.seq); err != nil {
			return rep, fmt.Errorf("seal record %d: %w", p.seq, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return rep, err
	}
	if _, err := VerifyPG(ctx, db, WithSealer(s)); err != nil {
		return rep, fmt.Errorf("the audit chain was sealed, but does not verify with the key: %w", err)
	}
	return rep, nil
}

// sealedFields reports whether a fields column holds the sealed form - a JSON string -
// rather than the record's own JSON, an object or null, which is what was written before
// the key.
func sealedFields(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && t[0] == '"'
}
