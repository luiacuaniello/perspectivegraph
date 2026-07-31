package kevholdout

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/threatintel"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// fakeIntel serves a fixed intel table, so a test can move KEV membership under a
// sealed forecast exactly the way time does in production.
type fakeIntel struct {
	table   map[string]threatintel.Intel
	enabled bool
	calls   int
}

func (f *fakeIntel) Enabled() bool { return f.enabled }
func (f *fakeIntel) Scores(_ context.Context, cves []string) map[string]threatintel.Intel {
	f.calls++
	out := map[string]threatintel.Intel{}
	for _, c := range cves {
		if in, ok := f.table[c]; ok {
			out[c] = in
		}
	}
	return out
}

type memSink struct {
	recs []validation.Record
	err  error
}

func (m *memSink) Put(r validation.Record) (validation.Record, error) {
	if m.err != nil {
		return validation.Record{}, m.err
	}
	m.recs = append(m.recs, r)
	return r, nil
}

func newRunner(t *testing.T, intel threatintel.Source, sink Sink, at time.Time) (*Runner, *Store) {
	t.Helper()
	st, err := NewStore(filepath.Join(t.TempDir(), "holdout.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	r := NewRunner(intel, st, sink, DefaultWindow, nil)
	r.now = func() time.Time { return at }
	return r, st
}

// The whole point of the package: a CVE that is ALREADY known-exploited carries no
// forecast, because the engine assigns it 0.95 from that very fact. Sealing it would
// grade the formula against its own input.
func TestAlreadyKnownExploitedIsNeverSealed(t *testing.T) {
	intel := &fakeIntel{enabled: true, table: map[string]threatintel.Intel{
		"CVE-2021-44228": {EPSS: 0.97, KEV: true},  // already exploited - no forecast to make
		"CVE-2024-0001":  {EPSS: 0.10, KEV: false}, // open question - forecastable
	}}
	sink := &memSink{}
	r, st := newRunner(t, intel, sink, time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC))

	res, err := r.Run(context.Background(), "default", []string{"CVE-2021-44228", "CVE-2024-0001"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Sealed != 1 {
		t.Fatalf("sealed %d forecasts, want exactly 1 (the non-KEV one)", res.Sealed)
	}
	for _, s := range st.Pending() {
		if s.CVE == "CVE-2021-44228" {
			t.Fatal("sealed a forecast for a CVE already in KEV: the measurement would be circular")
		}
	}
}

// A forecast must not be graded before its window closes - otherwise the outcome is
// read off the same evidence that produced the prediction.
func TestForecastIsNotGradedBeforeTheWindowCloses(t *testing.T) {
	intel := &fakeIntel{enabled: true, table: map[string]threatintel.Intel{
		"CVE-2024-0001": {EPSS: 0.4, KEV: false},
	}}
	sink := &memSink{}
	seal := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	r, _ := newRunner(t, intel, sink, seal)
	if _, err := r.Run(context.Background(), "default", []string{"CVE-2024-0001"}); err != nil {
		t.Fatalf("seal run: %v", err)
	}

	// One day short of the window, even though the CVE has since entered KEV.
	intel.table["CVE-2024-0001"] = threatintel.Intel{EPSS: 0.4, KEV: true}
	r.now = func() time.Time { return seal.Add(DefaultWindow - 24*time.Hour) }
	res, err := r.Run(context.Background(), "default", []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("early run: %v", err)
	}
	if res.Graded != 0 || len(sink.recs) != 0 {
		t.Fatalf("graded %d verdicts before the window closed, want 0", res.Graded)
	}
}

func TestGradesAgainstWhatHappenedAfterSealing(t *testing.T) {
	seal := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	intel := &fakeIntel{enabled: true, table: map[string]threatintel.Intel{
		"CVE-2024-0001": {EPSS: 0.60, KEV: false}, // will enter KEV  → confirmed
		"CVE-2024-0002": {EPSS: 0.02, KEV: false}, // will not        → refuted
	}}
	sink := &memSink{}
	cves := []string{"CVE-2024-0001", "CVE-2024-0002"}
	r, _ := newRunner(t, intel, sink, seal)
	if _, err := r.Run(context.Background(), "default", cves); err != nil {
		t.Fatalf("seal run: %v", err)
	}

	intel.table["CVE-2024-0001"] = threatintel.Intel{EPSS: 0.60, KEV: true}
	r.now = func() time.Time { return seal.Add(DefaultWindow + time.Hour) }
	res, err := r.Run(context.Background(), "default", cves)
	if err != nil {
		t.Fatalf("grade run: %v", err)
	}
	if res.Graded != 2 || res.Exploited != 1 {
		t.Fatalf("graded=%d exploited=%d, want 2 and 1", res.Graded, res.Exploited)
	}

	byCVE := map[string]validation.Record{}
	for _, rec := range sink.recs {
		byCVE[rec.Route] = rec
		if rec.Scope != validation.ScopeEdge {
			t.Errorf("%s: scope %q, want %q - edge verdicts must not grade S(P)", rec.Route, rec.Scope, validation.ScopeEdge)
		}
		if rec.PredictedScore <= 0 {
			t.Errorf("%s: no predicted score filed, so it cannot enter the calibration", rec.Route)
		}
	}
	if got := byCVE["CVE-2024-0001"].Outcome; got != validation.Confirmed {
		t.Errorf("CVE that entered KEV: outcome %q, want %q", got, validation.Confirmed)
	}
	if got := byCVE["CVE-2024-0002"].Outcome; got != validation.Refuted {
		t.Errorf("CVE that did not enter KEV: outcome %q, want %q", got, validation.Refuted)
	}
	// The prediction filed must be the one sealed BEFORE the outcome, not one recomputed
	// at grading time (which for the confirmed CVE would now be 0.95 - the circularity).
	if p := byCVE["CVE-2024-0001"].PredictedScore; p > 0.9 {
		t.Errorf("filed prediction %.2f looks recomputed at grading time; the sealed forecast was ~0.60", p)
	}
}

// Re-running before maturity must not restart the clock, or nothing ever comes due.
func TestResealingDoesNotRestartTheWindow(t *testing.T) {
	seal := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	intel := &fakeIntel{enabled: true, table: map[string]threatintel.Intel{
		"CVE-2024-0001": {EPSS: 0.4, KEV: false},
	}}
	r, st := newRunner(t, intel, &memSink{}, seal)
	cves := []string{"CVE-2024-0001"}
	if _, err := r.Run(context.Background(), "default", cves); err != nil {
		t.Fatalf("first: %v", err)
	}
	r.now = func() time.Time { return seal.Add(10 * 24 * time.Hour) }
	res, err := r.Run(context.Background(), "default", cves)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if res.Sealed != 0 {
		t.Fatalf("re-sealed %d open forecasts, want 0", res.Sealed)
	}
	if got := st.Pending()[0].SealedAt; !got.Equal(seal) {
		t.Fatalf("SealedAt moved to %v, want the original %v", got, seal)
	}
}

// Pending forecasts must survive a restart: the window is longer than any uptime you
// can rely on, so an in-memory-only store would never complete one.
func TestPendingForecastsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "holdout.json")
	seal := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	intel := &fakeIntel{enabled: true, table: map[string]threatintel.Intel{
		"CVE-2024-0001": {EPSS: 0.33, KEV: false},
	}}

	st1, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	r1 := NewRunner(intel, st1, &memSink{}, DefaultWindow, nil)
	r1.now = func() time.Time { return seal }
	if _, err := r1.Run(context.Background(), "default", []string{"CVE-2024-0001"}); err != nil {
		t.Fatalf("seal: %v", err)
	}

	st2, err := NewStore(path) // a fresh process
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	pending := st2.Pending()
	if len(pending) != 1 {
		t.Fatalf("%d forecasts after restart, want 1", len(pending))
	}
	if !pending[0].SealedAt.Equal(seal) || pending[0].Predicted <= 0 {
		t.Fatalf("forecast came back wrong: %+v", pending[0])
	}
}

// A sink failure must leave the forecast pending rather than discard it: these samples
// take a month each to produce.
func TestFilingFailureKeepsTheForecast(t *testing.T) {
	seal := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	intel := &fakeIntel{enabled: true, table: map[string]threatintel.Intel{
		"CVE-2024-0001": {EPSS: 0.4, KEV: false},
	}}
	sink := &memSink{}
	r, st := newRunner(t, intel, sink, seal)
	cves := []string{"CVE-2024-0001"}
	if _, err := r.Run(context.Background(), "default", cves); err != nil {
		t.Fatalf("seal: %v", err)
	}

	sink.err = errUnavailable
	r.now = func() time.Time { return seal.Add(DefaultWindow + time.Hour) }
	res, err := r.Run(context.Background(), "default", cves)
	if err != nil {
		t.Fatalf("grade: %v", err)
	}
	if res.Graded != 0 {
		t.Fatalf("counted %d graded despite the sink failing", res.Graded)
	}
	if len(st.Pending()) != 1 {
		t.Fatal("forecast was dropped after a failed file; a month of waiting would be lost")
	}
}

var errUnavailable = errStr("validation store unavailable")

type errStr string

func (e errStr) Error() string { return string(e) }

// A disabled intel source must be a no-op, so the feature stays dark until opted in.
func TestDisabledSourceDoesNothing(t *testing.T) {
	intel := &fakeIntel{enabled: false, table: map[string]threatintel.Intel{
		"CVE-2024-0001": {EPSS: 0.4},
	}}
	sink := &memSink{}
	r, st := newRunner(t, intel, sink, time.Now())
	res, err := r.Run(context.Background(), "default", []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Sealed != 0 || len(st.Pending()) != 0 || intel.calls != 0 {
		t.Fatalf("disabled source still did work: %+v, %d calls", res, intel.calls)
	}
}
