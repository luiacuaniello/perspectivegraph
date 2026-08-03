package validation

// On-disk format for the verdict store.
//
// The first version rewrote the ENTIRE dataset on every write: copy every record, sort
// them, MarshalIndent, encrypt the whole blob, write a temp file, rename. That is
// O(n log n) of CPU and a full re-encryption to record ONE verdict, in line with the
// request that produced it. It is invisible on a demo dataset and a wall on a real one -
// at 100k verdicts each new verdict rewrites megabytes, and the cost grows with exactly
// the thing the product wants customers to accumulate: calibration evidence.
//
// So the file is now an append-only log. One event per line, each independently sealed,
// so a write is one small append regardless of how much history precedes it. State is
// rebuilt by replaying the events through the same code path a live Put/Delete takes, so
// "what the log replays to" and "what the store holds" cannot drift apart.
//
// Per-line rather than per-file encryption is safe here because the sealer draws a fresh
// random 96-bit nonce per Seal (AES-256-GCM); with random nonces the birthday bound sits
// around 2^32 messages per key, which no verdict log approaches.
//
// Compaction rewrites the log as one event per live record whenever it has drifted far
// enough past the live set, which keeps replay bounded and amortises the rewrite to O(1)
// per write. The v1 whole-file format is still read, so existing deployments load
// unchanged and migrate on their first write.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// logMagicV2 is the plaintext first line that identifies the append-only format. It is
// deliberately NOT sealed: the format has to be detectable without a key, so a store
// opened with the wrong key fails on a record rather than being mistaken for v1.
const logMagicV2 = "#perspectivegraph-validation-log v2"

// logEvent is one mutation. Put carries the fully materialised record (id and timestamp
// already assigned), so replay never has to re-derive anything non-deterministic.
type logEvent struct {
	Op     string  `json:"op"`               // "put" | "del"
	Rec    *Record `json:"rec,omitempty"`    // op=put
	Tenant string  `json:"tenant,omitempty"` // op=del
	ID     string  `json:"id,omitempty"`     // op=del
}

// compactThreshold is the slack the log is allowed before a rewrite: twice the live set
// plus a floor so a small store is not compacted on every other write. Replay therefore
// never reads much more than twice what it materialises.
//
// Because the bound scales with the live set, compaction gets RARER as the store grows -
// roughly one rewrite per `live` writes - and a store that only accumulates (every
// verdict a new record) never compacts at all, since events and records grow together.
//
// A compaction is O(n) whatever else is true, but it does NOT hold the lock while it
// pays that cost - see compact. Readers wait only for the copy that starts it and the
// fold-and-rename that ends it, which is a different order of magnitude:
//
//	records   whole compaction   worst reader stall
//	  10k          12 ms                1 ms
//	  50k          70 ms                3 ms
//	 100k         161 ms                5 ms
//
// The compaction itself is marginally slower than the single-phase version it replaced
// (161 ms vs 137 ms at 100k - the extra copy and the fold are not free), and that is the
// trade being made deliberately: total time off the critical path went up slightly so
// that the time readers actually feel went down 27x.
func compactThreshold(live int) int { return 2*live + 64 }

// noteLocked records one event, with the lock held and the memory mutation already done.
//
// It only ever APPENDS - the O(1) path. When a full rewrite is required instead it says
// so and does nothing, leaving the caller to run compact() after releasing the lock. That
// split is the whole point: the expensive work must not happen inside the critical
// section.
//
// A full rewrite is required when there is no log to extend (a fresh store, or a v1 file
// being migrated), and after a failed append - in which case the event is on disk nowhere
// but is in memory, so the rewrite is what recovers it. The whole-file format this
// replaced self-healed on the next write, and losing that property would have been a real
// regression.
func (s *Store) noteLocked(ev logEvent) (needsRewrite bool, err error) {
	if s.path == "" {
		return false, nil
	}
	if s.dirty || s.legacy || s.logEvents == 0 {
		return true, nil
	}
	if err := s.appendLocked(ev); err != nil {
		s.dirty = true
		return true, err
	}
	// A compaction running right now is building its snapshot from a copy taken before
	// this event existed, so hand the event to it as well or the rewrite would silently
	// roll the store back to that snapshot.
	if s.compacting {
		s.pending = append(s.pending, ev)
	}
	return s.logEvents > compactThreshold(s.liveCountLocked()), nil
}

// appendLocked writes one encoded event to the tail of the current log.
func (s *Store) appendLocked(ev logEvent) error {
	line, err := s.encodeEvent(ev)
	if err != nil {
		return err
	}
	if err := appendLines(s.path, line); err != nil {
		return err
	}
	s.logEvents++
	return nil
}

func appendLines(path string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator-configured VALIDATIONS_PATH, not attacker-controlled
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Store) encodeEvent(ev logEvent) ([]byte, error) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	sealed, err := s.sealer.Seal(raw)
	if err != nil {
		return nil, err
	}
	// base64 so a sealed blob - arbitrary bytes, newlines included - stays on one line.
	line := make([]byte, 0, base64.StdEncoding.EncodedLen(len(sealed))+1)
	line = base64.StdEncoding.AppendEncode(line, sealed)
	return append(line, '\n'), nil
}

func (s *Store) liveCountLocked() int {
	n := 0
	for _, list := range s.byTenant {
		n += len(list)
	}
	return n
}

// compact rewrites the log as exactly one put per live record, WITHOUT holding the lock
// across the expensive part. The caller must not hold s.mu.
//
// Three phases, and the middle one is why this exists:
//
//  1. under the lock, copy the live records and open a pending buffer - O(n) memcpy, no
//     encryption and no I/O;
//  2. with NO lock held, encode, seal and write every record to a temp file - the 137 ms
//     at 100k records that used to stall every reader;
//  3. under the lock again, fold in the events that arrived during phase 2, rename, and
//     reset the bookkeeping.
//
// Writes during phase 2 keep appending to the CURRENT log, so that file stays complete
// and correct the whole time; they are additionally buffered into s.pending so phase 3
// can replay them onto the new file before the rename. If anything fails, the temp file
// is discarded and the current log - still authoritative - is untouched.
//
// This is synchronous on the write that triggers it: that one request pays the cost, and
// nothing else does. A background goroutine would spare even that request, at the price
// of a lifecycle to own, errors with no caller to return them to, and a shutdown race -
// too much machinery for an event this rare.
func (s *Store) compact() error {
	if s == nil || s.path == "" {
		return nil
	}

	// ── phase 1: snapshot ──────────────────────────────────────────────
	s.mu.Lock()
	if s.compacting {
		s.mu.Unlock()
		return nil // one at a time; the in-flight rewrite already covers this state
	}
	s.compacting = true
	s.pending = s.pending[:0]
	records := make([]Record, 0, s.liveCountLocked())
	for _, list := range s.byTenant {
		records = append(records, list...)
	}
	s.mu.Unlock()

	// ── phase 2: the expensive part, holding nothing ───────────────────
	// Deterministic order so a compacted log is reproducible and diffable.
	sort.Slice(records, func(i, j int) bool {
		if records[i].Tenant != records[j].Tenant {
			return records[i].Tenant < records[j].Tenant
		}
		return records[i].ID < records[j].ID
	})
	tmp, err := s.writeSnapshot(records)

	// ── phase 3: fold in concurrent writes, then swap ──────────────────
	s.mu.Lock()
	defer s.mu.Unlock()
	s.compacting = false
	defer func() { s.pending = nil }()

	if err != nil {
		return err
	}
	var folded bytes.Buffer
	for i := range s.pending {
		line, encErr := s.encodeEvent(s.pending[i])
		if encErr != nil {
			os.Remove(tmp)
			return encErr
		}
		folded.Write(line)
	}
	if err := appendLines(tmp, folded.Bytes()); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}

	s.logEvents = len(records) + len(s.pending)
	s.legacy = false
	s.dirty = false
	return nil
}

// writeSnapshot serialises records into a fresh temp file next to the log and returns its
// path. It touches no Store state beyond the sealer, so it is safe to call with no lock.
//
// A unique temp name (not a shared "<path>.tmp") so two writers cannot corrupt each
// other's partial write; the rename by the caller is atomic, and a crash mid-write leaves
// the previous log intact.
func (s *Store) writeSnapshot(records []Record) (string, error) {
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	tf, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".*.tmp")
	if err != nil {
		return "", err
	}
	tmp := tf.Name()

	var buf bytes.Buffer
	buf.WriteString(logMagicV2)
	buf.WriteByte('\n')
	for i := range records {
		line, err := s.encodeEvent(logEvent{Op: "put", Rec: &records[i]})
		if err != nil {
			tf.Close()
			os.Remove(tmp)
			return "", err
		}
		buf.Write(line)
	}
	if _, err := tf.Write(buf.Bytes()); err != nil {
		tf.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := tf.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// replayLog rebuilds state from an append-only log.
//
// A truncated FINAL line is tolerated and dropped: that is a write interrupted by a
// crash, and the event it describes never completed. A bad line anywhere else is real
// corruption - or the wrong key - and is reported rather than silently skipped, because
// quietly loading a subset of someone's calibration evidence and then grading a model
// against it is precisely the kind of confident wrongness this package exists to prevent.
func (s *Store) replayLog(b []byte) error {
	lines := bytes.Split(b, []byte("\n"))
	if len(lines) > 0 && bytes.Equal(bytes.TrimSpace(lines[0]), []byte(logMagicV2)) {
		lines = lines[1:]
	}

	// Index of the last line carrying anything, so "torn tail" is well defined.
	last := -1
	for i, ln := range lines {
		if len(bytes.TrimSpace(ln)) > 0 {
			last = i
		}
	}

	count := 0
	for i, ln := range lines {
		ln = bytes.TrimSpace(ln)
		if len(ln) == 0 {
			continue
		}
		ev, err := s.decodeEvent(ln)
		if err != nil {
			if i == last {
				break // torn tail from an interrupted append
			}
			return fmt.Errorf("validation: %s line %d: %w", s.path, i+1, err)
		}
		s.applyEventLocked(ev)
		count++
	}
	s.logEvents = count
	return nil
}

func (s *Store) decodeEvent(line []byte) (logEvent, error) {
	sealed, err := base64.StdEncoding.AppendDecode(nil, line)
	if err != nil {
		return logEvent{}, err
	}
	raw, err := s.sealer.Open(sealed)
	if err != nil {
		return logEvent{}, err
	}
	var ev logEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return logEvent{}, err
	}
	if ev.Op != "put" && ev.Op != "del" {
		return logEvent{}, errors.New("unknown op " + ev.Op)
	}
	if ev.Op == "put" && ev.Rec == nil {
		return logEvent{}, errors.New("put event carries no record")
	}
	return ev, nil
}

// applyEventLocked routes a replayed event through the SAME mutators a live call uses,
// which is what guarantees a reloaded store and a running one agree.
func (s *Store) applyEventLocked(ev logEvent) {
	switch ev.Op {
	case "put":
		s.applyPutLocked(*ev.Rec)
	case "del":
		s.applyDeleteLocked(ev.Tenant, ev.ID)
	}
}
