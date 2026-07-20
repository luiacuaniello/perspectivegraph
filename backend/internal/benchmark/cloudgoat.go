// Package benchmark runs the attack-path engine against CloudGoat-shaped
// scenarios as an independent ground-truth battery. Each scenario is a directory
// of real AWS describe-* fixtures (the exact shapes the aws connector consumes)
// plus a scenario.json that declares the attack paths the engine MUST find. The
// runner drives fixtures -> aws connector -> normalization -> in-memory graph ->
// analyzer, then scores the found paths against the declared ones as precision /
// recall - no AWS account, no network.
//
// Why this exists: the engine's per-edge probabilities are expert heuristics, and
// its threat-model scope (internet-origin by default, credential-origin opt-in)
// only became visible when validated against a real vulnerable lab (the M1
// exercise). A benchmark turns that one-off validation into a CI-gated regression:
//
//	recall < 1.0     -> the engine stopped finding a known attack path (false negative)
//	precision < 1.0  -> the engine invented a path that isn't real (false positive)
//
// The shipped fixtures are hand-authored to model each Rhino CloudGoat scenario's
// published attack path faithfully. To validate against genuine ground truth,
// replace a scenario's *.json with real `cloudgoat create` describe-* captures
// (see testdata/cloudgoat/README.md) - the runner is unchanged.
package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/connector/aws"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
)

// ExpectedPath is one attack path the engine is asserted to find. A found path
// matches it when its source and target names agree, it traverses every required
// node name/label, and its score clears MinScore. Fields left empty are not
// constrained, so a scenario can be as loose or as exact as its ground truth.
type ExpectedPath struct {
	ID                 string   `json:"id"`
	SourceName         string   `json:"source_name"`
	TargetName         string   `json:"target_name"`
	MustTraverseNames  []string `json:"must_traverse_names,omitempty"`
	MustTraverseLabels []string `json:"must_traverse_labels,omitempty"`
	MinScore           float64  `json:"min_score,omitempty"`
}

// Scenario is one CloudGoat-shaped test case: the fixtures live beside its
// scenario.json, and ExpectedPaths is the ground truth the engine is graded on.
type Scenario struct {
	Name          string `json:"name"`
	RhinoScenario string `json:"rhino_scenario,omitempty"`
	Description   string `json:"description"`
	// SeedIAMUsers selects the threat-model lens for this scenario: false =
	// internet-origin only (the default), true = also seed from IAM users (the
	// opt-in credential-origin lens). It mirrors the SEED_IAM_USERS env flag.
	SeedIAMUsers bool `json:"seed_iam_users"`
	// CredentialOrigin marks a scenario whose path exists ONLY under the
	// credential-origin lens. The runner additionally asserts that with the lens
	// OFF the scenario yields zero paths - encoding the M1 finding as a regression.
	CredentialOrigin bool `json:"credential_origin,omitempty"`
	// Exhaustive requires precision == 1.0: every crown-jewel path the engine finds
	// must be a declared one (no invented paths). Leave false when the fixtures may
	// legitimately produce paths beyond those enumerated.
	Exhaustive    bool           `json:"exhaustive,omitempty"`
	ExpectedPaths []ExpectedPath `json:"expected_paths"`
}

// Result is the graded outcome of one scenario run.
type Result struct {
	Scenario  string
	Expected  int      // declared paths
	Found     int      // crown-jewel paths the engine produced
	Matched   int      // declared paths covered by >= 1 found path
	Missing   []string // declared path IDs with no match (false negatives)
	Extra     []string // found paths matching no declared path (false positives)
	Precision float64  // found paths that are declared / found
	Recall    float64  // declared paths that are found / declared
}

// LoadScenario reads <dir>/scenario.json.
func LoadScenario(dir string) (Scenario, error) {
	var sc Scenario
	b, err := os.ReadFile(filepath.Join(dir, "scenario.json")) // #nosec G304 -- benchmark scenario dir, fixed filename
	if err != nil {
		return sc, err
	}
	if err := json.Unmarshal(b, &sc); err != nil {
		return sc, fmt.Errorf("decode scenario.json in %s: %w", dir, err)
	}
	if sc.Name == "" {
		sc.Name = filepath.Base(dir)
	}
	return sc, nil
}

// Paths builds the graph from a scenario's fixtures and returns the attack paths
// the engine finds - the same fixtures -> connector -> normalization -> analyzer
// path the live stack runs. It does NOT set the SEED_IAM_USERS toggle: the caller
// owns that global (see iam.SetSeedIAMUsers) so a scenario can be run under either
// lens without this package mutating process state behind the caller's back.
func Paths(ctx context.Context, dir string) ([]analyzer.AttackPath, error) {
	store := memory.New()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return store, nil })
	if err != nil {
		return nil, err
	}
	norm := normalization.New(mgr)

	events, err := aws.New(aws.Fixtures(dir)).Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("collect fixtures: %w", err)
	}
	for _, ev := range events {
		if err := norm.Handle(ctx, ev); err != nil {
			return nil, fmt.Errorf("apply event: %w", err)
		}
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return analyzer.FindCriticalPaths(snap), nil
}

// Grade scores found paths against a scenario's declared paths.
func Grade(sc Scenario, found []analyzer.AttackPath) Result {
	r := Result{Scenario: sc.Name, Expected: len(sc.ExpectedPaths), Found: len(found)}

	coveredExpected := make([]bool, len(sc.ExpectedPaths))
	foundIsDeclared := make([]bool, len(found))
	for i, p := range found {
		for j, e := range sc.ExpectedPaths {
			if pathMatches(p, e) {
				coveredExpected[j] = true
				foundIsDeclared[i] = true
			}
		}
	}

	for j, ok := range coveredExpected {
		if ok {
			r.Matched++
		} else {
			r.Missing = append(r.Missing, sc.ExpectedPaths[j].ID)
		}
	}
	truePos := 0
	for i, ok := range foundIsDeclared {
		if ok {
			truePos++
		} else {
			r.Extra = append(r.Extra, found[i].Source().Name+" -> "+found[i].Target().Name)
		}
	}

	// An empty ground truth that yields no paths is a perfect negative control.
	r.Recall = 1.0
	if r.Expected > 0 {
		r.Recall = float64(r.Matched) / float64(r.Expected)
	}
	r.Precision = 1.0
	if r.Found > 0 {
		r.Precision = float64(truePos) / float64(r.Found)
	}
	return r
}

// pathMatches reports whether a found attack path satisfies a declared one.
func pathMatches(p analyzer.AttackPath, e ExpectedPath) bool {
	if e.SourceName != "" && p.Source().Name != e.SourceName {
		return false
	}
	if e.TargetName != "" && p.Target().Name != e.TargetName {
		return false
	}
	if p.Score < e.MinScore {
		return false
	}
	names := make(map[string]bool, len(p.Nodes))
	labels := make(map[string]bool, len(p.Nodes))
	for _, n := range p.Nodes {
		names[n.Name] = true
		labels[string(n.Label)] = true
	}
	for _, want := range e.MustTraverseNames {
		if !names[want] {
			return false
		}
	}
	for _, want := range e.MustTraverseLabels {
		if !labels[want] {
			return false
		}
	}
	return true
}
