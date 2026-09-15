package config

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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
// installing npm over it: Node 24.20.0 ships npm 11.19.0. The image digest then pins npm
// cryptographically, which is a stronger guarantee than an unauthenticated
// `npm install -g`, and nothing is fetched at build time.
//
// The third drift is what that pin cost. Node was then WRITTEN OUT in four places - the
// Dockerfile, the Makefile's lockfile writer, and two exact `node-version`s in ci.yml -
// and Dependabot can edit only the first. Every rebuild of the Node image therefore
// arrived as a partial update: PR #204 moved the Dockerfile's floating `node:24-alpine`
// digest, which quietly carried Node 24.20.0 to 24.21.0, the Makefile kept the old digest,
// and this test refused it. Worse, the old test compared only the MAJOR between CI and
// the image, so with the Makefile updated too, CI on 24.20.0 and a release on 24.21.0
// would have passed. Now Node is named once, exactly, and everything else asks for it.
func TestNodeIsNamedOnceInTheReleaseDockerfile(t *testing.T) {
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

	// The one place: the release build stage, by exact version AND digest. A floating tag
	// like `24-alpine` is refused because it moves the Node version under a line that
	// looks unchanged, and no reader of the line can tell which Node it means.
	fromRe := regexp.MustCompile(`(?m)^FROM --platform=\$BUILDPLATFORM (node:(\d+\.\d+\.\d+)-alpine@sha256:[0-9a-f]{64}) AS build$`)
	dockerfile := read("frontend", "Dockerfile")
	from := fromRe.FindAllStringSubmatch(dockerfile, -1)
	if len(from) != 1 {
		t.Fatalf("frontend/Dockerfile has %d build stage(s) on node:X.Y.Z-alpine@sha256:<digest>, want exactly 1 - the exact version and the digest are both the pin", len(from))
	}
	image, version := from[0][1], from[0][2]
	if n := len(regexp.MustCompile(`(?m)^FROM .*node:`).FindAllString(dockerfile, -1)); n != 1 {
		t.Errorf("frontend/Dockerfile names Node in %d FROM lines, want 1", n)
	}

	// Everyone else asks the script, and the script answers with exactly that line. Run it,
	// rather than re-deriving its parse here: a test that re-implemented the regex would
	// pass while the script CI actually runs returned something else.
	for arg, want := range map[string]string{"": image, "--version": version} {
		args := []string{filepath.Join(root, "scripts", "node-image.sh")}
		if arg != "" {
			args = append(args, arg)
		}
		out, err := exec.Command("bash", args...).Output()
		if err != nil {
			t.Fatalf("scripts/node-image.sh %s: %v", arg, err)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("scripts/node-image.sh %s printed %q, but frontend/Dockerfile says %q", arg, got, want)
		}
	}

	// No other surface may write a Node version or image out again - that is exactly the
	// copy Dependabot does not update.
	literalRe := regexp.MustCompile(`node:\d|node-version: *["']?\d`)
	for _, f := range [][]string{{".github", "workflows", "ci.yml"}, {"Makefile"}} {
		if m := literalRe.FindString(read(f...)); m != "" {
			t.Errorf("%s writes Node out (%q); read it with scripts/node-image.sh instead, or the next Dependabot bump is partial again", filepath.Join(f...), m)
		}
	}
	ci := read(".github", "workflows", "ci.yml")
	setups := len(regexp.MustCompile(`uses: actions/setup-node@`).FindAllString(ci, -1))
	fromScript := len(regexp.MustCompile(`node-version: \$\{\{ steps\.node\.outputs\.version \}\}`).FindAllString(ci, -1))
	asked := len(regexp.MustCompile(`version="\$\(bash (\.\./)?scripts/node-image\.sh --version\)"`).FindAllString(ci, -1))
	if setups == 0 || fromScript != setups || asked != setups {
		t.Errorf("ci.yml: %d setup-node step(s), %d taking steps.node.outputs.version, %d reading scripts/node-image.sh --version into a variable - every setup-node must take the Dockerfile's Node, through an assignment that fails when the script does", setups, fromScript, asked)
	}
	if !strings.Contains(read("Makefile"), `"$$(scripts/node-image.sh)"`) {
		t.Error("the Makefile's lockfile writer does not take its image from scripts/node-image.sh")
	}

	// engines.npm documents the npm that Node ships, so a contributor on another one is
	// told by npm itself (EBADENGINE) rather than by a comment. It cannot be verified
	// against the image offline; it is checked here for shape, and CI's frontend job
	// compares it with the npm the pinned Node actually installed.
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
