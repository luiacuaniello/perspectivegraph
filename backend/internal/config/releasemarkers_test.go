package config

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A version string marked `x-release-please-version` is bumped by a release only when its
// file is listed in release-please-config.json's extra-files; the marker alone does
// nothing. A file that carries one and is not listed keeps naming the version it was
// written against, silently, release after release - in a compose file, that is an image
// nobody is patching any more: the single-VM recipe's backup service runs the database's
// image, and an unlisted pin would have dumped with an ever older pg_dump.
func TestEveryReleaseMarkerIsBumpedByTheRelease(t *testing.T) {
	root := repoRoot(t)

	var cfg struct {
		Packages map[string]struct {
			ExtraFiles []struct {
				Path string `json:"path"`
			} `json:"extra-files"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(mustRead(t, root, "release-please-config.json")), &cfg); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, p := range cfg.Packages {
		for _, f := range p.ExtraFiles {
			listed[f.Path] = true
		}
	}

	// Generated or third-party trees: the docs site copies docs/ at build time and caches
	// what it built in .astro, and dependencies are not ours to mark.
	skip := map[string]bool{
		".git": true, ".astro": true, "node_modules": true, "node_modules.nosync": true, "dist": true, "bin": true,
	}
	var unlisted []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skip[d.Name()] || rel == "site/src/content/docs" {
				return filepath.SkipDir
			}
			return nil
		}
		// The marker sits in text the release rewrites: docs, manifests, compose files.
		switch filepath.Ext(path) {
		case ".md", ".yml", ".yaml", ".json":
		default:
			return nil
		}
		b, err := os.ReadFile(path) // #nosec G304 -- a walk of this repository
		if err != nil {
			return err
		}
		if strings.Contains(string(b), "x-release-please-version") && !listed[rel] {
			unlisted = append(unlisted, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(unlisted) > 0 {
		sort.Strings(unlisted)
		t.Errorf("%d file(s) carry x-release-please-version but are not in release-please-config.json's "+
			"extra-files, so no release will ever bump them:\n  %s", len(unlisted), strings.Join(unlisted, "\n  "))
	}
}
