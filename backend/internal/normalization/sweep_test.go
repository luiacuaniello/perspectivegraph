package normalization

import (
	"context"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func imageScan(ref, lib string, taken time.Time, props map[string]any) ontology.Event {
	img := ontology.NewID(ontology.LabelImage, ref)
	libID := ontology.NewID(ontology.LabelLibrary, lib)
	return ontology.Event{Source: "trivy", ObservedAt: taken,
		Snapshot: &ontology.Snapshot{Scope: ontology.ImageScopePrefix + ref, Taken: taken},
		Nodes: []ontology.Node{{ID: img, Label: ontology.LabelImage, Name: ref, Properties: props},
			{ID: libID, Label: ontology.LabelLibrary, Name: lib}},
		Edges: []ontology.Edge{{Type: ontology.EdgeDependsOn, From: img, To: libID, ExploitProbability: 0.9}}}
}

func hasLib(t *testing.T, store *memory.Store, lib string) bool {
	t.Helper()
	snap, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, ok := snap.NodeByID()[ontology.NewID(ontology.LabelLibrary, lib)]
	return ok
}

// Two scans of one image under two registry spellings are one scope: the image's id is
// normalized, and so is the scope, in Handle and in Sweep alike. Otherwise the second
// scan could never retract what the first one said.
func TestAnImageScopeIsTheImageWhateverTheRegistrySpelling(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	n := New(managerFor(ctx, t, store))
	t0, t1 := time.Now().Add(-time.Hour), time.Now()
	if err := n.Handle(ctx, imageScan("docker.io/library/app:1.0", "log4j@2.14", t0, nil)); err != nil {
		t.Fatal(err)
	}
	if err := n.Handle(ctx, imageScan("app:1.0", "log4j@2.17", t1, nil)); err != nil {
		t.Fatal(err)
	}
	// The broker hands Sweep the scope as the event carried it, before normalization.
	if err := n.Sweep(ctx, "default", "trivy", "image:app:1.0", t1); err != nil {
		t.Fatal(err)
	}
	if hasLib(t, store, "log4j@2.14") || !hasLib(t, store, "log4j@2.17") {
		t.Fatal("the rescan under another registry spelling did not retract the old library")
	}
}

// A pull request's event is recorded as a partial observation, however it reached the
// bus with a declaration: the webhook refuses to declare one complete, and a declaration
// that got through is dropped by the rule the broker schedules sweeps by as well. What it
// brought stays until staleness pruning, and the next complete scan of the running image
// does not take it for its own.
func TestAPullRequestsEventIsAPartialObservation(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	n := New(managerFor(ctx, t, store))
	t0, t1, t2 := time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), time.Now()
	if err := n.Handle(ctx, imageScan("app:1.0", "log4j@2.14", t0, nil)); err != nil {
		t.Fatal(err)
	}
	pr := imageScan("app:1.0", "log4j@2.17", t1, map[string]any{ontology.PropRepoSlug: "acme/app", ontology.PropCommitSHA: "abc"})
	if pr.CompleteSnapshot() != nil {
		t.Fatal("a pull request's event passes for a complete snapshot")
	}
	if err := n.Handle(ctx, pr); err != nil {
		t.Fatal(err)
	}
	if err := n.Handle(ctx, imageScan("app:1.0", "log4j@2.14", t2, nil)); err != nil {
		t.Fatal(err)
	}
	if err := n.Sweep(ctx, "default", "trivy", "image:app:1.0", t2); err != nil {
		t.Fatal(err)
	}
	if !hasLib(t, store, "log4j@2.17") {
		t.Fatal("the pull request's library was recorded under the image's scope and retracted by its next scan")
	}
}
