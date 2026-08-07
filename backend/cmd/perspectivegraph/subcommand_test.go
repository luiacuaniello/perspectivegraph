package main

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// The dispatch in main() and the `subcommands` list next to it are two statements of the
// same fact, and nothing but this test keeps them equal. A drifted list is worse than no
// list: it tells an operator their spelling was wrong about a command that exists, or
// advertises one that does not.
//
// This reads the source rather than calling anything, because the dispatch is a series of
// early returns inside main() - there is nothing to call.
func TestUnknownSubcommandMessageListsEveryRealSubcommand(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}

	re := regexp.MustCompile(`os\.Args\[1\] == "([a-z-]+)"`)
	var dispatched []string
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		if !slices.Contains(dispatched, m[1]) {
			dispatched = append(dispatched, m[1])
		}
	}
	if len(dispatched) < 5 {
		t.Fatalf("found only %v in the dispatch - the pattern this test scans for has changed", dispatched)
	}

	for _, name := range dispatched {
		if !slices.Contains(subcommands, name) {
			t.Errorf("%q is dispatched but missing from subcommands, so `perspectivegraph %s` is not advertised", name, name)
		}
	}
	for _, name := range subcommands {
		if !slices.Contains(dispatched, name) {
			t.Errorf("subcommands advertises %q but nothing dispatches it", name)
		}
	}
}

// gate is the one a CI runner invokes, and the one whose absence used to be invisible: an
// older release fell through to starting the server and hung the job until its timeout.
func TestGateIsAdvertised(t *testing.T) {
	if !slices.Contains(subcommands, "gate") {
		t.Error("gate is not in subcommands, so a release too old to have it cannot be told apart from a typo")
	}
}
