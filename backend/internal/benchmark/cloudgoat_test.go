package benchmark

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
)

const scenarioRoot = "../../testdata/cloudgoat"

// TestCloudGoatBenchmark grades the attack-path engine against every scenario
// under testdata/cloudgoat. It is the CI-gated regression: any scenario that
// loses a declared path (recall < 1) or invents one (precision < 1, when the
// scenario is exhaustive) fails the build. It runs under `go test ./...`, so no
// extra CI wiring is needed; `make bench-cloudgoat` runs it verbosely to print
// the precision/recall table.
func TestCloudGoatBenchmark(t *testing.T) {
	scenarios := discoverScenarios(t)
	if len(scenarios) == 0 {
		t.Fatalf("no scenarios found under %s", scenarioRoot)
	}

	for _, dir := range scenarios {
		sc, err := LoadScenario(dir)
		if err != nil {
			t.Fatalf("load %s: %v", dir, err)
		}

		t.Run(sc.Name, func(t *testing.T) {
			// The seed lens is process-global; own it explicitly and restore it so
			// scenarios can't leak their lens into one another.
			iam.SetSeedIAMUsers(sc.SeedIAMUsers)
			t.Cleanup(func() { iam.SetSeedIAMUsers(false) })

			found, err := Paths(context.Background(), dir)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			res := Grade(sc, found)

			t.Logf("%-30s lens=%s recall=%.2f precision=%.2f (matched %d/%d, found %d)",
				sc.Name, lens(sc.SeedIAMUsers), res.Recall, res.Precision, res.Matched, res.Expected, res.Found)

			if res.Recall < 1.0 {
				t.Errorf("recall %.2f < 1.0 - engine no longer finds declared path(s): %v", res.Recall, res.Missing)
			}
			if sc.Exhaustive && res.Precision < 1.0 {
				t.Errorf("precision %.2f < 1.0 - engine produced undeclared path(s): %v", res.Precision, res.Extra)
			}

			// Credential-origin scenarios must NOT form a path under the default
			// internet-origin lens: this pins the M1 finding (a leaked-credential
			// privesc is invisible until the operator opts into SEED_IAM_USERS).
			if sc.CredentialOrigin {
				iam.SetSeedIAMUsers(false)
				withoutLens, err := Paths(context.Background(), dir)
				if err != nil {
					t.Fatalf("run (lens off): %v", err)
				}
				if len(withoutLens) != 0 {
					t.Errorf("credential-origin scenario formed %d path(s) with SEED_IAM_USERS off; expected 0", len(withoutLens))
				}
			}
		})
	}
}

// discoverScenarios returns every subdirectory of scenarioRoot that carries a
// scenario.json.
func discoverScenarios(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(scenarioRoot)
	if err != nil {
		t.Fatalf("read %s: %v", scenarioRoot, err)
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(scenarioRoot, e.Name())
		if _, err := os.Stat(filepath.Join(dir, "scenario.json")); err == nil {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	return dirs
}

func lens(seedIAMUsers bool) string {
	if seedIAMUsers {
		return "credential"
	}
	return "internet"
}
