package validation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
)

func rec(pathID string, o Outcome) Record {
	return Record{PathID: pathID, Outcome: o, Source: "test", Tenant: "acme"}
}

func mustPut(t *testing.T, s *Store, r Record) Record {
	t.Helper()
	got, err := s.Put(r)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return got
}

// The point of the append-only log: a write must cost the same whether the store holds
// ten verdicts or ten thousand. The previous format rewrote, re-sorted and re-encrypted
// the whole dataset per verdict, so this ratio grew without bound - and it grew with
// exactly the thing the product asks customers to accumulate.
func TestWriteCostDoesNotGrowWithDatasetSize(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "v.log"))
	if err != nil {
		t.Fatal(err)
	}

	measure := func(n int) time.Duration {
		start := time.Now()
		for i := 0; i < n; i++ {
			mustPut(t, s, rec("", Missed)) // Missed accumulates: the store really grows
		}
		return time.Since(start) / time.Duration(n)
	}

	early := measure(300) // store now holds ~300
	for i := 0; i < 4000; i++ {
		mustPut(t, s, rec("", Missed))
	}
	late := measure(300) // store now holds ~4600, 15x bigger

	if s.liveCountLocked() < 4000 {
		t.Fatalf("store only holds %d records - the test did not grow it", s.liveCountLocked())
	}
	// Generous: the old format was strictly linear, so at 15x the data it was ~15x the
	// cost. Anything near constant passes; a linear regression fails loudly.
	if late > 5*early {
		t.Fatalf("per-write cost grew from %v to %v (%.1fx) as the store grew 15x - writes are not O(1)",
			early, late, float64(late)/float64(early))
	}
	t.Logf("per-write: %v at ~300 records, %v at ~4600", early, late)
}

// Replay must reproduce the live store exactly, including the replacement rule (a new
// path-scoped verdict supersedes the previous one for that path) and deletions.
func TestLogRoundTripsThroughReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.log")

	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, s, rec("ap-1", Confirmed))
	mustPut(t, s, rec("ap-2", Refuted))
	mustPut(t, s, rec("ap-1", Partial)) // supersedes the ap-1 verdict above
	doomed := mustPut(t, s, rec("ap-3", Confirmed))
	mustPut(t, s, rec("", Missed))
	if err := s.Delete("acme", doomed.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	before := s.List("acme")

	reloaded, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	after := reloaded.List("acme")

	if len(before) != len(after) {
		t.Fatalf("reloaded %d records, live store had %d", len(after), len(before))
	}
	bj, _ := json.Marshal(before)
	aj, _ := json.Marshal(after)
	if string(bj) != string(aj) {
		t.Errorf("reloaded state differs from live state:\n live: %s\n disk: %s", bj, aj)
	}
	for _, r := range after {
		if r.ID == doomed.ID {
			t.Error("a deleted verdict came back after reload")
		}
		if r.PathID == "ap-1" && r.Outcome != Partial {
			t.Errorf("ap-1 reloaded as %q, want the superseding verdict %q", r.Outcome, Partial)
		}
	}
}

// Encryption at rest still applies, now per line. The file must not contain plaintext,
// and must reload with the same key.
func TestLogStaysSealedAtRest(t *testing.T) {
	sealer, err := cryptostore.New(strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "v.log")

	s, err := New(path, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, s, Record{PathID: "ap-secret", Outcome: Confirmed, Source: "test",
		Tenant: "acme", Evidence: "TOTALLY-SECRET-EVIDENCE"})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "TOTALLY-SECRET-EVIDENCE") || strings.Contains(string(raw), "ap-secret") {
		t.Fatal("verdict contents are readable on disk despite a sealer")
	}

	reloaded, err := New(path, WithSealer(sealer))
	if err != nil {
		t.Fatalf("reload with the same key: %v", err)
	}
	if got := reloaded.List("acme"); len(got) != 1 || got[0].Evidence != "TOTALLY-SECRET-EVIDENCE" {
		t.Fatalf("sealed round-trip lost the record: %+v", got)
	}
}

// Existing deployments hold v1 files. They must keep loading, and loading must not
// rewrite them - an operator who starts and stops the binary should find the file as
// they left it. Migration happens on the first write.
func TestLegacyFileLoadsAndMigratesOnFirstWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.json")

	legacy := fileShape{Records: []Record{
		{ID: "vd-old1", PathID: "ap-1", Tenant: "acme", Outcome: Confirmed, Source: "legacy", TestedAt: time.Now().UTC()},
		{ID: "vd-old2", PathID: "ap-2", Tenant: "acme", Outcome: Refuted, Source: "legacy", TestedAt: time.Now().UTC()},
	}}
	b, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatalf("loading a v1 file: %v", err)
	}
	if got := len(s.List("acme")); got != 2 {
		t.Fatalf("loaded %d legacy records, want 2", got)
	}
	if after, _ := os.ReadFile(path); string(after) != string(b) {
		t.Error("loading rewrote the file - load must be read-only")
	}

	mustPut(t, s, rec("ap-3", Confirmed))

	after, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(after), logMagicV2) {
		t.Fatalf("first write did not migrate the file to v2: %.40q", after)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reloaded.List("acme")); got != 3 {
		t.Fatalf("after migration the store holds %d records, want 3 (2 legacy + 1 new)", got)
	}
}

// Compaction has to actually run, or replay cost grows without bound even though each
// individual write is cheap.
func TestLogCompactsAsItGrows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.log")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	// Re-verdicting the same path repeatedly: each write appends an event but the live
	// set stays at one record, which is the worst case for log drift.
	for i := 0; i < 500; i++ {
		mustPut(t, s, rec("ap-1", Confirmed))
	}
	if live := s.liveCountLocked(); live != 1 {
		t.Fatalf("live set is %d, want 1 - the replacement rule did not apply", live)
	}
	if s.logEvents > compactThreshold(1) {
		t.Fatalf("log holds %d events for 1 live record - compaction never ran", s.logEvents)
	}

	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reloaded.List("acme")); got != 1 {
		t.Fatalf("compacted log replays to %d records, want 1", got)
	}
}

// A crash during an append leaves a partial final line. That event never completed, so
// dropping it is correct - and the records before it must survive.
func TestTornFinalLineIsTolerated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.log")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	mustPut(t, s, rec("ap-1", Confirmed))
	mustPut(t, s, rec("ap-2", Confirmed))

	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(b, []byte("dGhpcyBpcyBhIHRvcn")...), 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := New(path)
	if err != nil {
		t.Fatalf("a torn tail made the whole store unreadable: %v", err)
	}
	if got := len(reloaded.List("acme")); got != 2 {
		t.Fatalf("recovered %d records after a torn tail, want 2", got)
	}
}

// Corruption in the MIDDLE is not a torn write. Loading a silent subset of someone's
// calibration evidence and then grading a model against it is the failure this package
// exists to prevent, so it must be an error.
func TestMidFileCorruptionIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.log")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		mustPut(t, s, rec("", Missed))
	}

	lines := strings.Split(string(mustRead(t, path)), "\n")
	lines[2] = "!!!! not base64 !!!!"
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := New(path); err == nil {
		t.Fatal("a corrupted line in the middle of the log loaded silently")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
