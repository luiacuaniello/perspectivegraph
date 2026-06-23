// Package audit is a tamper-evident, append-only audit log.
//
// Each record carries the SHA-256 hash of the previous record, forming a hash
// chain: altering or deleting any past entry breaks every hash after it, so
// tampering is detectable by re-walking the chain (Verify). Records are written
// as one JSON object per line (JSONL), fsync'd, so the file is append-only and
// survives a crash. This is the pragmatic, dependency-free "WORM" an MVP needs;
// shipping the chain head to an external notary (or a managed append-only store)
// is the production hardening.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

// Record is one audit entry. Hash is sha256 over the canonical encoding of all
// fields including PrevHash, so the chain is verifiable end-to-end.
type Record struct {
	Seq      int64          `json:"seq"`
	Time     time.Time      `json:"time"`
	Action   string         `json:"action"` // "api" | "ingest" | "auth.deny" | …
	Subject  string         `json:"subject"`
	Role     string         `json:"role,omitempty"`
	Tenant   string         `json:"tenant,omitempty"`
	Fields   map[string]any `json:"fields,omitempty"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// Recorder appends audit records. Implementations must be safe for concurrent
// use by the HTTP middlewares.
type Recorder interface {
	Record(action, subject, role, tenant string, fields map[string]any)
}

// Nop discards records (audit disabled).
type Nop struct{}

func (Nop) Record(string, string, string, string, map[string]any) {}

// Log is a file-backed, hash-chained Recorder.
type Log struct {
	mu       sync.Mutex
	f        *os.File
	w        *bufio.Writer
	seq      int64
	prevHash string
	sealer   cryptostore.Sealer
}

// Option configures a Log (or Verify).
type Option func(*cryptostore.Sealer)

// WithSealer encrypts each record at rest. The hash chain still runs over the
// plaintext record, so tamper-evidence and confidentiality compose; lines
// written before encryption was enabled are still read (transparent migration).
// The default Nop sealer writes plaintext JSONL.
func WithSealer(sealer cryptostore.Sealer) Option {
	return func(s *cryptostore.Sealer) {
		if sealer != nil {
			*s = sealer
		}
	}
}

func sealerFrom(opts []Option) cryptostore.Sealer {
	s := cryptostore.Nop()
	for _, opt := range opts {
		opt(&s)
	}
	return s
}

// Open opens (or creates) the audit log at path, resuming the chain from the
// last record so appends continue the existing chain.
func Open(path string, opts ...Option) (*Log, error) {
	sealer := sealerFrom(opts)
	seq, prev, err := tail(path, sealer)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Log{f: f, w: bufio.NewWriter(f), seq: seq, prevHash: prev, sealer: sealer}, nil
}

// encodeLine renders a record line for the file: plaintext JSON when the sealer
// is off, else base64(sealed(json)). decodeLine inverts it, treating a line that
// starts with '{' as plaintext (base64 output never does), so mixed files read.
func encodeLine(line []byte, sealer cryptostore.Sealer) ([]byte, error) {
	if !sealer.Enabled() {
		return line, nil
	}
	sealed, err := sealer.Seal(line)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(sealed)), nil
}

func decodeLine(line []byte, sealer cryptostore.Sealer) ([]byte, error) {
	if len(line) > 0 && line[0] == '{' {
		return line, nil // plaintext JSON (sealer off, or a pre-encryption record)
	}
	raw, err := base64.StdEncoding.DecodeString(string(line))
	if err != nil {
		return nil, fmt.Errorf("audit: undecodable line: %w", err)
	}
	return sealer.Open(raw)
}

func (l *Log) Record(action, subject, role, tenant string, fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := Record{
		Seq:      l.seq + 1,
		Time:     time.Now().UTC(),
		Action:   action,
		Subject:  subject,
		Role:     role,
		Tenant:   tenant,
		Fields:   fields,
		PrevHash: l.prevHash,
	}
	rec.Hash = hashRecord(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	out, err := encodeLine(line, l.sealer)
	if err != nil {
		return
	}
	if _, err := l.w.Write(append(out, '\n')); err != nil {
		return
	}
	if err := l.w.Flush(); err != nil {
		return
	}
	_ = l.f.Sync() // durability: an audit entry that isn't on disk didn't happen

	l.seq = rec.Seq
	l.prevHash = rec.Hash
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.w.Flush()
	return l.f.Close()
}

// hashRecord computes the chain hash over everything but Hash itself.
func hashRecord(r Record) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// tail returns the last seq + hash in an existing log (0, "" if absent).
func tail(path string, sealer cryptostore.Sealer) (int64, string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	var last Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		dec, err := decodeLine(line, sealer)
		if err != nil {
			return 0, "", err
		}
		if err := json.Unmarshal(dec, &last); err != nil {
			return 0, "", fmt.Errorf("corrupt audit log line: %w", err)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, "", err
	}
	return last.Seq, last.Hash, nil
}

// Verify re-walks the chain in path and returns an error at the first record
// whose hash or back-link doesn't match - i.e. evidence of tampering.
func Verify(path string, opts ...Option) (records int, err error) {
	sealer := sealerFrom(opts)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()

	prev := ""
	var seq int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		dec, err := decodeLine(line, sealer)
		if err != nil {
			return records, fmt.Errorf("record %d: %w", records+1, err)
		}
		var rec Record
		if err := json.Unmarshal(dec, &rec); err != nil {
			return records, fmt.Errorf("record %d: %w", records+1, err)
		}
		if rec.PrevHash != prev {
			return records, fmt.Errorf("record %d (seq %d): broken chain link", records+1, rec.Seq)
		}
		if rec.Seq != seq+1 {
			return records, fmt.Errorf("record %d: seq jumped to %d", records+1, rec.Seq)
		}
		if hashRecord(rec) != rec.Hash {
			return records, fmt.Errorf("record %d (seq %d): hash mismatch (tampered)", records+1, rec.Seq)
		}
		prev = rec.Hash
		seq = rec.Seq
		records++
	}
	return records, sc.Err()
}
