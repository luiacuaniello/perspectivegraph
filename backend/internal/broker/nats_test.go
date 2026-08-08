package broker

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeSubject(t *testing.T) {
	cases := []struct {
		in, wantStream, wantBase string
	}{
		{"perspective.events.*", "perspective.events.>", "perspective.events"},
		{"perspective.events.>", "perspective.events.>", "perspective.events"},
		{"perspective.events", "perspective.events.>", "perspective.events"},
		{"perspective.events.", "perspective.events.>", "perspective.events"},
		{"  custom.bus  ", "custom.bus.>", "custom.bus"},
		{"", "perspective.events.>", "perspective.events"},
	}
	for _, c := range cases {
		stream, base := normalizeSubject(c.in)
		if stream != c.wantStream || base != c.wantBase {
			t.Errorf("normalizeSubject(%q) = (%q, %q), want (%q, %q)",
				c.in, stream, base, c.wantStream, c.wantBase)
		}
	}
}

func TestSubjectForSanitizesSource(t *testing.T) {
	b := &Broker{base: "perspective.events"}
	cases := map[string]string{
		"trivy":      "perspective.events.trivy",
		"my.scanner": "perspective.events.my-scanner", // dots would add subject tokens
		"a b*c>d":    "perspective.events.a-b-c-d",    // spaces and wildcards
		"":           "perspective.events.unknown",
	}
	for in, want := range cases {
		if got := b.subjectFor(in); got != want {
			t.Errorf("subjectFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBackoffForClampsToSchedule(t *testing.T) {
	if got := backoffFor(1); got != time.Second {
		t.Errorf("first retry = %v, want 1s", got)
	}
	if got := backoffFor(99); got != time.Minute {
		t.Errorf("retries beyond the schedule = %v, want the last delay (1m)", got)
	}
	if got := backoffFor(0); got != time.Second {
		t.Errorf("defensive attempt=0 = %v, want 1s", got)
	}
}

// The redelivery boundary, which is off-by-one country and decides whether a transient
// failure recovers or an event is lost.
//
// `attempt` is NumDelivered: 1 on the FIRST delivery. So the cap is reached when it
// equals maxDeliver, not when it exceeds it. Give up one delivery early and an event
// that would have succeeded on its last retry is dead-lettered - a node missing from the
// graph, hence an attack path that never appears. Give up one late and a permanently
// failing event is redelivered for ever and the backlog behind it never drains.
func TestRetryOrDeadLetterBoundary(t *testing.T) {
	for _, tc := range []struct {
		attempt uint64
		giveUp  bool
		why     string
	}{
		{1, false, "the first delivery must always be retried"},
		{2, false, "well inside the budget"},
		{maxDeliver - 1, false, "the last attempt that still has a retry left"},
		{maxDeliver, true, "the budget is spent when attempt EQUALS maxDeliver"},
		{maxDeliver + 1, true, "and stays spent beyond it"},
		{1 << 20, true, "an absurd count must not wrap into another retry"},
	} {
		delay, giveUp := retryOrDeadLetter(tc.attempt)
		if giveUp != tc.giveUp {
			t.Errorf("attempt %d: giveUp=%v, want %v - %s", tc.attempt, giveUp, tc.giveUp, tc.why)
		}
		if giveUp && delay != 0 {
			t.Errorf("attempt %d: delay %v alongside give-up, which would be silently ignored", tc.attempt, delay)
		}
		if !giveUp && delay <= 0 {
			t.Errorf("attempt %d: delay %v - a zero backoff redelivers immediately and spins", tc.attempt, delay)
		}
	}
}

// Every retry must wait, and the waits must not shrink as attempts pile up: a schedule
// that went backwards would hammer a failing dependency hardest just as it gives up.
func TestBackoffNeverShrinks(t *testing.T) {
	var prev time.Duration
	for attempt := uint64(1); attempt < maxDeliver; attempt++ {
		d, giveUp := retryOrDeadLetter(attempt)
		if giveUp {
			t.Fatalf("attempt %d gave up before maxDeliver=%d", attempt, maxDeliver)
		}
		if d < prev {
			t.Errorf("attempt %d waits %v, less than the %v before it", attempt, d, prev)
		}
		prev = d
	}
}

// The dead-letter subject must sit OUTSIDE the stream the consumer reads, or a poisoned
// message is republished into the very stream it was removed from and loops for ever.
func TestDeadLetterSubjectIsOutsideTheEventStream(t *testing.T) {
	_, base := normalizeSubject("perspective.events")
	dlq := dlqSubjectFor("PERSPECTIVE")
	if strings.HasPrefix(dlq, base+".") || dlq == base {
		t.Fatalf("dlq subject %q is inside the event base %q - a poison message would be redelivered for ever", dlq, base)
	}
	// And two deployments sharing a NATS must not claim the same subject, or the
	// second refuses to start.
	if dlqSubjectFor("PROD") == dlqSubjectFor("STAGING") {
		t.Error("the dead-letter subject is not scoped to the stream, so two deployments collide")
	}
}
