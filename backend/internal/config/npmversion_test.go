package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// npm is pinned, and this holds every place that installs it to one declared version.
//
// It lives beside the deploy-parity test for the same reason that one exists: these are
// repository surfaces that must agree, the drift is silent, and nothing else in the build
// compares them. A Go test is where this project already keeps that kind of check.
//
// The drift it was written after: CI ran whatever npm the Node image bundled (10.9.8),
// and npm 10 posts its audit to the legacy `security/audits/quick` endpoint while current
// npm posts to `security/advisories/bulk`. A 503 on the legacy endpoint failed a build on
// 2026-09-04 - on an API the project's own npm no longer calls. The version a base image
// happens to ship is not a decision, and it was deciding which service the supply-chain
// gate depended on.
//
// package.json `engines.npm` is the source: npm itself reads it, so a contributor on a
// different npm is told by their own tooling rather than by a comment.
func TestNpmVersionIsPinnedEverywhereItRuns(t *testing.T) {
	root := repoRoot(t)

	var pkg struct {
		Engines struct {
			NPM string `json:"npm"`
		} `json:"engines"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "frontend", "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}
	want := pkg.Engines.NPM
	if want == "" {
		t.Fatal("frontend/package.json declares no engines.npm; it is the source this test reads")
	}
	// An exact version, not a range: a range cannot be installed reproducibly, and "the
	// newest that satisfies" is the unpinned behaviour this replaced.
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(want) {
		t.Fatalf("engines.npm = %q; it must be an exact version, since every call site installs it verbatim", want)
	}

	// Every file that installs npm, and how many times it must do so. A count rather than
	// a boolean: the licences job was added to CI later than the frontend job, and a check
	// that only asked "does this file mention the version" would have passed while one of
	// the two jobs still ran the bundled npm.
	installRe := regexp.MustCompile(`npm install -g npm@([0-9][^\s'"]*)`)
	for _, tc := range []struct {
		path  []string
		count int
		why   string
	}{
		{[]string{".github", "workflows", "ci.yml"}, 2, "the frontend job (which audits) and the licences job"},
		{[]string{"Makefile"}, 1, "the lockfile target - the only thing that WRITES package-lock.json"},
		{[]string{"frontend", "Dockerfile"}, 1, "the release image build"},
	} {
		name := filepath.Join(tc.path...)
		b, err := os.ReadFile(filepath.Join(append([]string{root}, tc.path...)...))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		found := installRe.FindAllStringSubmatch(string(b), -1)
		if len(found) != tc.count {
			t.Errorf("%s installs npm %d time(s), want %d (%s)", name, len(found), tc.count, tc.why)
			continue
		}
		for _, m := range found {
			if got := m[1]; got != want {
				t.Errorf("%s installs npm@%s, but frontend/package.json declares %s", name, got, want)
			}
		}
	}
}
