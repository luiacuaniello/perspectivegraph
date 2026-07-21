package redteam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// FixtureOracle settles assertions from a fixed table, so the whole runner is
// testable with no AWS account: it plays the role reality plays live. It is the
// deterministic stand-in for a captured lab run - "in this environment, principal X's
// escalation was DENIED by an SCP" - which is exactly the `refuted` signal the
// flywheel needs, without the flywheel's author deciding the outcome per path.
type FixtureOracle struct {
	decisions map[string]Result
	fallback  Decision
}

// fixtureFile is the on-disk shape a captured lab produces: a default decision plus
// per-assertion overrides keyed by Assertion.Key().
type fixtureFile struct {
	Fallback  string            `json:"fallback"` // "allowed" | "denied" | "inconclusive"
	Decisions map[string]Result `json:"decisions"`
}

// NewFixtureOracle builds an oracle from an in-memory decision table. Keys are
// Assertion.Key() values; the fallback applies to any assertion not listed.
func NewFixtureOracle(decisions map[string]Result, fallback Decision) *FixtureOracle {
	if decisions == nil {
		decisions = map[string]Result{}
	}
	return &FixtureOracle{decisions: decisions, fallback: fallback}
}

// LoadFixtureOracle reads a fixture file (see fixtureFile). A key that names an
// unknown decision string is rejected, so a typo fails loudly rather than silently
// defaulting to "allowed".
func LoadFixtureOracle(path string) (*FixtureOracle, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test/lab fixture path, operator-supplied
	if err != nil {
		return nil, err
	}
	var f fixtureFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("decode fixture %s: %w", path, err)
	}
	fallback, err := parseDecision(f.Fallback)
	if err != nil {
		return nil, fmt.Errorf("fixture %s fallback: %w", path, err)
	}
	return NewFixtureOracle(f.Decisions, fallback), nil
}

// Check looks up the assertion's decision, falling back to the configured default.
func (f *FixtureOracle) Check(_ context.Context, a Assertion) (Result, error) {
	if r, ok := f.decisions[a.Key()]; ok {
		return r, nil
	}
	return Result{Decision: f.fallback, Evidence: "fixture fallback"}, nil
}

// parseDecision maps a decision string to a Decision, rejecting unknown values.
func parseDecision(s string) (Decision, error) {
	switch s {
	case "allowed":
		return Allowed, nil
	case "denied":
		return Denied, nil
	case "", "inconclusive":
		return Inconclusive, nil
	default:
		return Inconclusive, fmt.Errorf("unknown decision %q", s)
	}
}

// UnmarshalJSON lets Result decode either a bare decision string ("denied") or the
// full object ({"decision":"denied","evidence":"…"}), so fixtures stay terse.
func (r *Result) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		d, err := parseDecision(s)
		if err != nil {
			return err
		}
		r.Decision, r.Evidence = d, ""
		return nil
	}
	var obj struct {
		Decision string `json:"decision"`
		Evidence string `json:"evidence"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	d, err := parseDecision(obj.Decision)
	if err != nil {
		return err
	}
	r.Decision, r.Evidence = d, obj.Evidence
	return nil
}
