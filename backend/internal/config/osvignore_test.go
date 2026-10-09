package config

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// An osv-scanner.toml tells OpenSSF Scorecard that an advisory does not affect its module.
// An ignore is a claim, and a claim nothing re-checks goes stale silently: the day a
// dependency starts importing the advised package, the file would keep hiding it. So every
// ignored advisory names the package it is about here, and the test asks the Go toolchain
// whether that package is compiled into any binary or test - of the backend, and of the
// single-VM recipe's Caddy (deploy/caddy), a module of its own.
func TestIgnoredAdvisoriesStayUnreachable(t *testing.T) {
	for _, module := range [][]string{{"backend"}, {"deploy", "caddy"}} {
		t.Run(filepath.Join(module...), func(t *testing.T) {
			checkIgnoredAdvisories(t, filepath.Join(append([]string{repoRoot(t)}, module...)...))
		})
	}
}

func checkIgnoredAdvisories(t *testing.T, dir string) {
	packageOf := map[string]string{
		"GO-2026-5932": "golang.org/x/crypto/openpgp",
	}

	ignored := regexp.MustCompile(`(?m)^id = "([^"]+)"`).FindAllStringSubmatch(mustRead(t, dir, "osv-scanner.toml"), -1)
	if len(ignored) == 0 {
		t.Fatal("osv-scanner.toml ignores nothing - delete the file rather than keep an empty one")
	}

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH to list the build's packages")
	}
	cmd := exec.Command(goBin, "list", "-deps", "-test", "./...")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	compiled := map[string]bool{}
	for _, pkg := range strings.Fields(string(out)) {
		compiled[pkg] = true
	}

	for _, m := range ignored {
		id := m[1]
		pkg, known := packageOf[id]
		if !known {
			t.Errorf("%s is ignored in osv-scanner.toml but not checked here: name the package it advises against", id)
			continue
		}
		for p := range compiled {
			if p == pkg || strings.HasPrefix(p, pkg+"/") {
				t.Errorf("%s is ignored, but %s is now compiled in (%s): the reason in osv-scanner.toml is no longer true", id, pkg, p)
			}
		}
	}
}
