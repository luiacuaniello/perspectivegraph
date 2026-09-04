package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Node - and therefore npm - is pinned once, and this holds every place that names it.
//
// Beside the deploy-parity and Go-version tests for the same reason: repository surfaces
// that must agree, drift that is silent, nothing else in the build comparing them.
//
// Two drifts are recorded here, both real. The first: CI ran whatever npm the Node image
// bundled (10.9.8), and npm 10 posts its audit to the legacy `security/audits/quick`
// endpoint while current npm posts to `security/advisories/bulk`. A 503 on the legacy one
// failed a build on 2026-09-04, on an API the project's own npm no longer calls.
//
// The second is the fix for the first, which was worse: `npm install -g npm@11.19.1` in
// the workflows and the release Dockerfile pinned the VERSION but fetched it from the
// registry unverified, which OpenSSF Scorecard reports as three unpinned dependencies -
// trading a determinism problem for a supply-chain one.
//
// Both are answered by choosing a Node whose bundled npm is the one wanted, rather than
// installing npm over it: Node 24.20.0 ships npm 11.19.0. The image digest and the exact
// `node-version` then pin npm cryptographically, which is a stronger guarantee than an
// unauthenticated `npm install -g`, and nothing is fetched at build time.
func TestNodeAndNpmArePinnedByOneVersion(t *testing.T) {
	root := repoRoot(t)
	read := func(parts ...string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
		if err != nil {
			t.Fatalf("%s: %v", filepath.Join(parts...), err)
		}
		return string(b)
	}

	// Nothing may install npm over the one the image ships. This is the regression guard
	// for the Scorecard findings: the install is what made npm an unpinned dependency.
	installRe := regexp.MustCompile(`npm install -g npm@`)
	for _, f := range [][]string{
		{".github", "workflows", "ci.yml"},
		{"frontend", "Dockerfile"},
		{"Makefile"},
	} {
		if installRe.MatchString(read(f...)) {
			t.Errorf("%s installs npm globally; the Node image's own npm is pinned by digest, an unauthenticated `npm install -g` is not - and Scorecard reports it as an unpinned dependency",
				filepath.Join(f...))
		}
	}

	// The Node version CI resolves, exact: "24" would float onto a different npm.
	ver := regexp.MustCompile(`node-version: "(\d+\.\d+\.\d+)"`).FindAllStringSubmatch(read(".github", "workflows", "ci.yml"), -1)
	if len(ver) != 2 {
		t.Fatalf("ci.yml pins node-version %d time(s), want 2 (the frontend job and the licences job)", len(ver))
	}
	want := ver[0][1]
	for _, m := range ver {
		if m[1] != want {
			t.Errorf("ci.yml pins two different Node versions: %s and %s", want, m[1])
		}
	}

	// The container surfaces pin the same Node by DIGEST - the release build and the
	// lockfile writer must be the same image, or the lockfile is written by an npm the
	// release never runs.
	digestRe := regexp.MustCompile(`node:(\d+)-alpine@(sha256:[0-9a-f]{64})`)
	var digest string
	for _, f := range [][]string{{"frontend", "Dockerfile"}, {"Makefile"}} {
		m := digestRe.FindStringSubmatch(read(f...))
		if m == nil {
			t.Errorf("%s does not reference node:<major>-alpine pinned by digest", filepath.Join(f...))
			continue
		}
		if major := want[:len(regexp.MustCompile(`^\d+`).FindString(want))]; m[1] != major {
			t.Errorf("%s uses node:%s-alpine but ci.yml pins Node %s", filepath.Join(f...), m[1], want)
		}
		if digest == "" {
			digest = m[2]
		} else if m[2] != digest {
			t.Errorf("%s pins a different node image digest than the other surface does", filepath.Join(f...))
		}
	}

	// engines.npm documents the npm that Node ships, so a contributor on another one is
	// told by npm itself (EBADENGINE) rather than by a comment. It cannot be verified
	// against the image offline; it is checked for shape and for being stated at all.
	var pkg struct {
		Engines struct {
			NPM string `json:"npm"`
		} `json:"engines"`
	}
	if err := json.Unmarshal([]byte(read("frontend", "package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(pkg.Engines.NPM) {
		t.Errorf("frontend/package.json engines.npm = %q, want the exact npm the pinned Node ships", pkg.Engines.NPM)
	}
}
