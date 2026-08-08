package basimport

import "testing"

func paths() []PathInfo {
	return []PathInfo{
		{ID: "p-low", From: "edge-alb", Target: "account-admin (effective)", Priority: 20},
		{ID: "p-high", From: "public-lb", Target: "account-admin (effective)", Priority: 91},
		{ID: "p-other", From: "edge-alb", Target: "secrets-vault", Priority: 55},
	}
}

// A tester who names the path has said which one they mean; nothing may second-guess it.
func TestExplicitPathIDWins(t *testing.T) {
	got, ok := Resolve(paths(), "p-low", "secrets-vault", "edge-alb")
	if !ok || got != "p-low" {
		t.Fatalf("got (%q,%v), want the id the tester gave", got, ok)
	}
}

// The formatting difference this exists to absorb: a tester writes what they typed into
// their tool, the engine holds what the cloud calls it. Demanding an exact match would
// discard a real outcome over "(effective)".
func TestTargetMatchesOnASubstringIgnoringCase(t *testing.T) {
	for _, target := range []string{"account-admin", "ACCOUNT-ADMIN", "admin (effective)"} {
		if _, ok := Resolve(paths(), "", target, ""); !ok {
			t.Errorf("%q matched nothing, so a real verdict would be dropped", target)
		}
	}
}

// When several paths reach the same asset, the verdict belongs to the one an operator
// would have been looking at - the highest priority - not to whichever the graph
// happened to list first.
func TestHighestPriorityWinsAmongCandidates(t *testing.T) {
	got, ok := Resolve(paths(), "", "account-admin", "")
	if !ok {
		t.Fatal("no match")
	}
	if got != "p-high" {
		t.Errorf("resolved to %q; the verdict would be recorded against a path the tester was not looking at", got)
	}
}

// The entry point narrows the match, so a tester who reached admin from one door is not
// credited against the path through another.
func TestEntryPointNarrowsTheMatch(t *testing.T) {
	got, ok := Resolve(paths(), "", "account-admin", "edge-alb")
	if !ok || got != "p-low" {
		t.Fatalf("got (%q,%v), want the lower-priority path that actually starts at edge-alb", got, ok)
	}
	if _, ok := Resolve(paths(), "", "account-admin", "nonexistent-door"); ok {
		t.Error("matched despite an entry point no path has")
	}
}

// Reporting "no match" is the point of the boolean: recording a verdict against an
// arbitrary path would grade the engine on something nobody tested, and the error would
// be invisible in the calibration numbers afterwards.
func TestNoMatchIsReportedRatherThanGuessed(t *testing.T) {
	for name, tc := range map[string]struct{ target, from string }{
		"unknown target": {"nothing-like-this", ""},
		"empty target":   {"", ""},
		"wrong entry":    {"account-admin", "not-a-door"},
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := Resolve(paths(), "", tc.target, tc.from); ok {
				t.Errorf("resolved to %q instead of reporting no match", got)
			}
		})
	}
	if _, ok := Resolve(nil, "", "account-admin", ""); ok {
		t.Error("matched against an empty path set")
	}
}
