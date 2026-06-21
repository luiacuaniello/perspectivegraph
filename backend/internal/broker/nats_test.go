package broker

import (
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
