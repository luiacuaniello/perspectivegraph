package action

import (
	"context"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type fakeStatus struct {
	calls []string // "slug@sha=state"
}

func (f *fakeStatus) forge() string { return "github" }
func (f *fakeStatus) enabled() bool { return true }
func (f *fakeStatus) postStatus(_ context.Context, slug, sha, state, _, _ string) error {
	f.calls = append(f.calls, slug+"@"+sha+"="+state)
	return nil
}

// pathWithPR builds a path whose entry node carries PR commit context.
func pathWithPR(slug, sha, jewel string) analyzer.AttackPath {
	return analyzer.AttackPath{Nodes: []ontology.Node{
		{ID: "lb", Properties: map[string]any{ontology.PropRepoSlug: slug, ontology.PropCommitSHA: sha}},
		{ID: "jewel", Name: jewel, Properties: map[string]any{ontology.PropCrownJewel: true}},
	}}
}

// TestCheckFailsThenResolves: a PR on a critical path goes red; when the next
// pass no longer has it, the same commit flips green.
func TestCheckFailsThenResolves(t *testing.T) {
	fp := &fakeStatus{}
	r := newStatusReporter(fp, "")
	ctx := context.Background()

	// Pass 1: the PR's change sits on a critical path → failure.
	r.OnCriticalPaths(ctx, []analyzer.AttackPath{pathWithPR("acme/web", "deadbeef", "customers-db")})
	if len(fp.calls) != 1 || fp.calls[0] != "acme/web@deadbeef=failure" {
		t.Fatalf("expected one failure status, got %v", fp.calls)
	}

	// Pass 2: path gone (fixed) → the same commit flips to success.
	r.OnCriticalPaths(ctx, nil)
	if len(fp.calls) != 2 || fp.calls[1] != "acme/web@deadbeef=success" {
		t.Fatalf("expected a success status on resolution, got %v", fp.calls)
	}
}

// TestCheckSkipsPathsWithoutCommit: no commit SHA → nothing to attach a status to.
func TestCheckSkipsPathsWithoutCommit(t *testing.T) {
	fp := &fakeStatus{}
	r := newStatusReporter(fp, "")
	// PR slug but no commit sha.
	p := analyzer.AttackPath{Nodes: []ontology.Node{
		{ID: "lb", Properties: map[string]any{ontology.PropRepoSlug: "acme/web"}},
		{ID: "j", Properties: map[string]any{ontology.PropCrownJewel: true}},
	}}
	r.OnCriticalPaths(context.Background(), []analyzer.AttackPath{p})
	if len(fp.calls) != 0 {
		t.Errorf("a path without a commit sha must not post a status, got %v", fp.calls)
	}
}
