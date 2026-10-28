package config

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every image this project builds starts from a base that has to be kept patched, and the
// bundled database's was not: no Dependabot entry watched deploy/postgres, so its base moved
// only when the scan of a release found something to fix. A Dockerfile added without an
// entry is caught here rather than by the next scan.
func TestEveryDockerfileIsWatchedByDependabot(t *testing.T) {
	root := repoRoot(t)
	entry := regexp.MustCompile(`(?m)^\s*-\s*package-ecosystem:\s*docker\s*\n\s*directory:\s*(\S+)`)
	watched := map[string]bool{}
	for _, m := range entry.FindAllStringSubmatch(mustRead(t, root, ".github", "dependabot.yml"), -1) {
		watched["/"+strings.Trim(m[1], "/")] = true
	}

	var unwatched []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", ".astro":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "Dockerfile" {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			return err
		}
		dir := "/"
		if rel != "." {
			dir += filepath.ToSlash(rel)
		}
		if !watched[dir] {
			unwatched = append(unwatched, dir)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(unwatched)
	if len(unwatched) > 0 {
		t.Errorf("no `package-ecosystem: docker` entry in .github/dependabot.yml watches %s, so the base "+
			"image there is never proposed for an update", strings.Join(unwatched, ", "))
	}
}
