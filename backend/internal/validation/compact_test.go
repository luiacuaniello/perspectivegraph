package validation

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowSealer makes phase 2 of a compaction take a controllable, observable amount of
// time. It goes in through the public WithSealer option, so none of the machinery below
// requires a test-only hook inside the store.
type slowSealer struct{ per time.Duration }

func (s slowSealer) Seal(b []byte) ([]byte, error) { time.Sleep(s.per); return b, nil }
func (slowSealer) Open(b []byte) ([]byte, error)   { return b, nil }
func (slowSealer) Enabled() bool                   { return true }

// countingSealer is slowSealer that counts what it seals, so a test can tell how far a
// compaction's lock-free phase - which seals every record it rewrites - has got.
type countingSealer struct {
	per    time.Duration
	sealed atomic.Int64
}

func (s *countingSealer) Seal(b []byte) ([]byte, error) {
	time.Sleep(s.per)
	s.sealed.Add(1)
	return b, nil
}
func (*countingSealer) Open(b []byte) ([]byte, error) { return b, nil }
func (*countingSealer) Enabled() bool                 { return true }

// failAfterSealer fails once it has sealed n blobs, so a compaction can be made to fail
// in the middle of writing its snapshot.
type failAfterSealer struct {
	mu sync.Mutex
	n  int
}

func (f *failAfterSealer) Seal(b []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n <= 0 {
		return nil, errors.New("sealer exhausted")
	}
	f.n--
	return b, nil
}
func (*failAfterSealer) Open(b []byte) ([]byte, error) { return b, nil }
func (*failAfterSealer) Enabled() bool                 { return true }

// waitUntilCompacting blocks until a compaction has taken its snapshot and released the
// lock - i.e. it is inside the phase that holds nothing.
func waitUntilCompacting(t *testing.T, s *Store) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		in := s.compacting
		s.mu.Unlock()
		if in {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("compaction never entered its lock-free phase")
		}
		runtime.Gosched()
	}
}

func seed(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		mustPut(t, s, Record{PathID: fmt.Sprintf("seed-%d", i), Outcome: Missed, Source: "seed", Tenant: "acme"})
	}
}

// The property the whole three-phase design has to buy: a verdict recorded WHILE a
// compaction is encoding its snapshot must survive the swap. The snapshot was copied
// before that verdict existed, so without the pending buffer the rename would silently
// roll the store back - losing an accepted write with no error anywhere.
func TestWritesDuringCompactionSurviveTheSwap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.log")
	s, err := New(path, WithSealer(slowSealer{per: 2 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s, 60) // phase 2 will take ~120ms

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.compact(); err != nil {
			t.Errorf("compact: %v", err)
		}
	}()

	waitUntilCompacting(t, s)
	for i := 0; i < 15; i++ {
		mustPut(t, s, Record{PathID: fmt.Sprintf("during-%d", i), Outcome: Missed, Source: "concurrent", Tenant: "acme"})
	}
	wg.Wait()

	want := lenOf(s.List(context.Background(), "acme"))
	if want != 75 {
		t.Fatalf("live store holds %d records, expected 60 seeded + 15 concurrent", want)
	}
	reloaded, err := New(path, WithSealer(slowSealer{}))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, _ := reloaded.List(context.Background(), "acme")
	if len(got) != want {
		t.Fatalf("compacted log replays to %d records but the store holds %d - concurrent writes were lost", len(got), want)
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[r.PathID] = true
	}
	for i := 0; i < 15; i++ {
		if !seen[fmt.Sprintf("during-%d", i)] {
			t.Errorf("verdict during-%d, accepted during compaction, is not on disk", i)
		}
	}
}

// The reason for moving the encode out of the critical section. A reader must not wait
// for a compaction: it used to block for the full rewrite - 137 ms at 100k records.
//
// Judged by how far the compaction had got when the reads returned, not by a deadline on
// them: a reader serialised behind it could only return once its lock-free phase had sealed
// every record, while a loaded machine slows the reads and the compaction alike - the
// 40 ms this once allowed measured the machine as much as the lock.
func TestReadersAreNotBlockedByCompaction(t *testing.T) {
	sealer := &countingSealer{per: 2 * time.Millisecond}
	s, err := New(filepath.Join(t.TempDir(), "v.log"), WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s, 60) // ~120ms of phase 2
	sealer.sealed.Store(0)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = s.compact() }()
	waitUntilCompacting(t, s)

	for i := 0; i < 5; i++ {
		_, _ = s.List(context.Background(), "acme")
		_, _ = s.Metrics(context.Background(), "acme")
	}
	during := sealer.sealed.Load()
	wg.Wait()
	total := sealer.sealed.Load()

	if total == 0 {
		t.Fatal("the compaction sealed nothing: this test no longer reaches its lock-free phase")
	}
	if during >= total {
		t.Fatalf("the reads returned only after the compaction had sealed all %d records - readers are blocked by it", total)
	}
	t.Logf("reads returned when the compaction had sealed %d of %d records", during, total)
}

// A failed compaction must leave the store exactly as it was. The current log already
// holds every event, so the temp file is discarded and nothing is swapped in.
func TestFailedCompactionLeavesTheLogIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.log")
	sealer := &failAfterSealer{n: 1 << 20}
	s, err := New(path, WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s, 20)
	before, _ := s.List(context.Background(), "acme")

	sealer.mu.Lock()
	sealer.n = 5 // the next compaction dies partway through its snapshot
	sealer.mu.Unlock()

	if err := s.compact(); err == nil {
		t.Fatal("a compaction whose sealer failed reported success")
	}

	sealer.mu.Lock()
	sealer.n = 1 << 20
	sealer.mu.Unlock()

	reloaded, err := New(path, WithSealer(sealer))
	if err != nil {
		t.Fatalf("the log is unreadable after a failed compaction: %v", err)
	}
	if got := lenOf(reloaded.List(context.Background(), "acme")); got != len(before) {
		t.Fatalf("log holds %d records after a failed compaction, want %d", got, len(before))
	}
	if s.compacting {
		t.Error("the compacting flag was left set after a failure")
	}
	if s.pending != nil {
		t.Error("the pending buffer was left behind after a failure")
	}
}

// Two compactions must not run at once: the second would snapshot state the first is
// already rewriting, and whichever renamed last would win with a stale file.
//
// Judged by what was sealed, not by how fast the second call returned: declining, it
// returns while the first is still sealing and seals nothing itself, so the two together
// seal what one compaction does.
func TestOnlyOneCompactionRunsAtATime(t *testing.T) {
	sealer := &countingSealer{per: 2 * time.Millisecond}
	s, err := New(filepath.Join(t.TempDir(), "v.log"), WithSealer(sealer))
	if err != nil {
		t.Fatal(err)
	}
	seed(t, s, 60)
	sealer.sealed.Store(0)
	if err := s.compact(); err != nil {
		t.Fatal(err)
	}
	one := sealer.sealed.Load() // what one compaction of this store seals
	sealer.sealed.Store(0)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = s.compact() }()
	waitUntilCompacting(t, s)

	// While the first is in phase 2, a second must decline rather than start its own
	// snapshot.
	if err := s.compact(); err != nil {
		t.Fatalf("the declined compaction returned an error: %v", err)
	}
	during := sealer.sealed.Load()
	wg.Wait()
	total := sealer.sealed.Load()

	if one == 0 {
		t.Fatal("a compaction sealed nothing: this test no longer reaches its lock-free phase")
	}
	if during >= one {
		t.Fatalf("the second compaction returned only after %d records were sealed, a whole compaction's %d - it did not decline", during, one)
	}
	if total != one {
		t.Fatalf("the two compactions sealed %d records, one compaction seals %d - the second ran", total, one)
	}
}

// Everything at once, which is what -race is for: concurrent writers, deleters and
// readers while compactions trigger naturally. The store must end up agreeing with its
// own log.
func TestConcurrentWritersReadersAndCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.log")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := []string{}

	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				// A fixed set of path ids keeps the live set small while the event
				// count climbs - the shape that actually triggers compaction.
				r, err := s.Put(context.Background(), Record{PathID: fmt.Sprintf("ap-%d", i%10), Outcome: Confirmed, Source: "w", Tenant: "acme"})
				if err != nil {
					t.Errorf("Put: %v", err)
					return
				}
				mu.Lock()
				ids = append(ids, r.ID)
				mu.Unlock()
			}
		}(w)
	}
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				_, _ = s.List(context.Background(), "acme")
				_, _ = s.Metrics(context.Background(), "acme")
				_, _ = s.Calibration(context.Background(), "acme")
			}
		}()
	}
	wg.Wait()

	// Delete a few, then confirm disk and memory still agree.
	mu.Lock()
	sample := ids[:5]
	mu.Unlock()
	for _, id := range sample {
		if err := s.Delete(context.Background(), "acme", id); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete: %v", err)
		}
	}

	live, _ := s.List(context.Background(), "acme")
	reloaded, err := New(path)
	if err != nil {
		t.Fatalf("reload after concurrent load: %v", err)
	}
	if got := lenOf(reloaded.List(context.Background(), "acme")); got != len(live) {
		t.Fatalf("log replays to %d records, store holds %d", got, len(live))
	}
}

// lenOf counts a (slice, error) read in a test that only cares about the count.
func lenOf[T any](v []T, _ error) int { return len(v) }
