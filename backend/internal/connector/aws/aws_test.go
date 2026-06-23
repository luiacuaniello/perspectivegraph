package aws

import (
	"context"
	"testing"
)

const testdata = "../../../testdata"

// TestCollectFromFixtures proves the reuse: the AWS connector, pointed at local
// describe-* JSON, produces the same cloudnet + iam events the upload path does -
// with no AWS account in sight.
func TestCollectFromFixtures(t *testing.T) {
	c := New(Fixtures(testdata))
	if c.Source() != "aws" || c.Mode() != "fixtures" {
		t.Fatalf("source/mode = %q/%q", c.Source(), c.Mode())
	}

	events, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected events from the fixtures")
	}

	bySource := map[string]int{}
	nodes := 0
	for _, ev := range events {
		bySource[ev.Source]++
		nodes += len(ev.Nodes)
	}
	if bySource["cloudnet"] == 0 {
		t.Error("expected cloudnet (network) events")
	}
	if bySource["iam"] == 0 {
		t.Error("expected iam events")
	}
	if nodes == 0 {
		t.Error("expected the parsed events to carry nodes")
	}
}

// TestMissingFixturesIsNotFatal: an absent feed file is skipped, not an error,
// so a dir with only some feeds (or none) degrades cleanly.
func TestMissingFixturesIsNotFatal(t *testing.T) {
	c := New(Fixtures("/nonexistent-dir-xyz"))
	events, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("missing fixtures should not error, got: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("missing fixtures should yield no events, got %d", len(events))
	}
}
