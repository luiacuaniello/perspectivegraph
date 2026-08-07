package main

import (
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/build"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/custodian"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/dataclass"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/falco"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/semgrep"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/sso"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/supplychain"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/trivy"
)

// allCollectors is the one list of tools this binary can parse, shared by the ingest
// server and by the gate's local mode.
//
// It is one list on purpose. The two callers answer the same question by different
// routes - "what does this scanner output mean for the graph" - and a tool that existed
// on one route but not the other would make a commit analysable through the server and
// UNKNOWN through the gate, or the reverse. That divergence would be invisible until it
// mattered.
func allCollectors() []ingestion.Collector {
	return []ingestion.Collector{
		trivy.New(), semgrep.New(), custodian.New(), falco.New(), build.New(), k8s.New(),
		cloudnet.New(), iam.New(), supplychain.New(), sso.New(), dataclass.New(),
	}
}

// collectorFor returns the collector that parses a tool's output, by source name.
func collectorFor(source string) (ingestion.Collector, bool) {
	for _, c := range allCollectors() {
		if c.Source() == source {
			return c, true
		}
	}
	return nil, false
}

// collectorNames lists what -source accepts, for error messages.
func collectorNames() []string {
	cs := allCollectors()
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Source())
	}
	return out
}
