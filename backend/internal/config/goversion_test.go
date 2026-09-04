package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Go toolchain is named in seventeen places, and they have to agree.
//
// Beside the npm and deploy-parity tests for the same reason: these are repository
// surfaces that must match, the drift is silent, and nothing else in the build compares
// them. The Go version is worse than most, because it is spelt three different ways -
// `toolchain go1.26.7`, `go-version: "1.26.7"`, `golang:1.26.7-alpine` - so a grep for one
// spelling finds none of the others.
//
// The drift it was written after: moving the project to Go 1.26 raised the `toolchain`
// line, both Dockerfiles, every CI job and every script, and left the `go` DIRECTIVE at
// 1.25.0. That directive is the module's declared minimum, and the README badge reads it,
// so the front page advertised a Go version the project could not actually be built with:
// staticcheck, a required gate, needs 1.26 to run at all.
func TestGoVersionIsConsistentEverywhereItIsNamed(t *testing.T) {
	root := repoRoot(t)

	read := func(parts ...string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
		if err != nil {
			t.Fatalf("%s: %v", filepath.Join(parts...), err)
		}
		return string(b)
	}

	// go.mod is the source: `toolchain` is the version the project actually builds with.
	gomod := read("backend", "go.mod")
	tc := regexp.MustCompile(`(?m)^toolchain go(\d+\.\d+\.\d+)$`).FindStringSubmatch(gomod)
	if tc == nil {
		t.Fatal("backend/go.mod declares no toolchain line; it is the source this test reads")
	}
	want := tc[1] // e.g. 1.26.7
	minor := want[:strings.LastIndex(want, ".")]

	// The `go` directive is the module's declared MINIMUM, and the README badge reads it.
	// It may trail the toolchain by a patch - a patch release fixes bugs, it does not add
	// language - but not by a minor: that advertises a Go the project cannot be built with.
	gd := regexp.MustCompile(`(?m)^go (\d+\.\d+)(?:\.\d+)?$`).FindStringSubmatch(gomod)
	if gd == nil {
		t.Fatal("backend/go.mod declares no go directive")
	}
	if gd[1] != minor {
		t.Errorf("backend/go.mod: go directive is %s but the toolchain is %s - the README badge reads the directive, so it would advertise %s",
			gd[1], want, gd[1])
	}

	// Every other spelling, with the count each file must carry. Counts rather than
	// booleans: a workflow that gained a second Go job would otherwise pass on the first.
	for _, tc := range []struct {
		path  []string
		re    string
		count int
	}{
		{[]string{"backend", "Dockerfile"}, `golang:(\d+\.\d+\.\d+)-alpine`, 1},
		{[]string{".github", "workflows", "ci.yml"}, `go-version: "(\d+\.\d+\.\d+)"`, 3},
		{[]string{".github", "workflows", "codeql.yml"}, `go-version: "(\d+\.\d+\.\d+)"`, 1},
		{[]string{".github", "workflows", "fuzz.yml"}, `go-version: "(\d+\.\d+\.\d+)"`, 1},
		{[]string{".github", "workflows", "publish-images.yml"}, `go-version: "(\d+\.\d+\.\d+)"`, 1},
		{[]string{".github", "workflows", "action-smoke.yml"}, `go-version: "(\d+\.\d+\.\d+)"`, 2},
	} {
		name := filepath.Join(tc.path...)
		found := regexp.MustCompile(tc.re).FindAllStringSubmatch(read(tc.path...), -1)
		if len(found) != tc.count {
			t.Errorf("%s names a Go version %d time(s), want %d", name, len(found), tc.count)
			continue
		}
		for _, m := range found {
			if m[1] != want {
				t.Errorf("%s pins Go %s, but backend/go.mod's toolchain is %s", name, m[1], want)
			}
		}
	}

	// The scripts default GOTOOLCHAIN, so a developer running them gets the same compiler
	// CI does rather than whatever is on their PATH.
	scripts, err := filepath.Glob(filepath.Join(root, "scripts", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	gt := regexp.MustCompile(`GOTOOLCHAIN=?["{:]*\$?\{?GOTOOLCHAIN:-go(\d+\.\d+\.\d+)`)
	pinned := 0
	for _, s := range scripts {
		for _, m := range gt.FindAllStringSubmatch(read("scripts", filepath.Base(s)), -1) {
			pinned++
			if m[1] != want {
				t.Errorf("scripts/%s defaults GOTOOLCHAIN to go%s, want go%s", filepath.Base(s), m[1], want)
			}
		}
	}
	if pinned == 0 {
		t.Error("no script defaults GOTOOLCHAIN; this test would silently check nothing")
	}
}
