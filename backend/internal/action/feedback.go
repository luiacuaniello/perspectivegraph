// Package action is the feedback layer. It consumes critical attack paths and
// turns them into something actionable: a console/PR-comment diagram today,
// and (roadmap) GitHub PR comments, policy-invariant failures, and
// auto-remediation patches.
package action

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// MultiSink fans a single analysis result out to several sinks (e.g. console
// logging + GitHub PR comments).
type MultiSink []analyzer.Sink

func (m MultiSink) OnCriticalPaths(ctx context.Context, paths []analyzer.AttackPath) {
	for _, s := range m {
		s.OnCriticalPaths(ctx, paths)
	}
}

// ConsoleSink renders critical paths to the log. It satisfies analyzer.Sink.
type ConsoleSink struct{}

func (ConsoleSink) OnCriticalPaths(_ context.Context, paths []analyzer.AttackPath) {
	for _, p := range paths {
		slog.Warn("critical attack path detected",
			"id", p.ID,
			"score", fmt.Sprintf("%.2f", p.Score),
			"source", p.Source().Name,
			"target", p.Target().Name,
			"hops", len(p.Steps),
		)
		fmt.Print(RenderPath(p))
	}
}

// RenderPath returns a human-readable, tree-style diagram of an attack path,
// suitable for a PR comment body or terminal output.
func RenderPath(p analyzer.AttackPath) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n🚨 Critical Attack Path  (score %.2f, %d hops)\n", p.Score, len(p.Steps))

	for i, n := range p.Nodes {
		indent := strings.Repeat("   ", i)
		fmt.Fprintf(&b, "%s%s [%s] %s%s\n", indent, connector(i), n.Label, n.Name, badges(n))
		if i < len(p.Steps) {
			st := p.Steps[i]
			fmt.Fprintf(&b, "%s   └─%s (p=%.2f)─▶\n", indent, st.EdgeType, st.Probability)
		}
	}
	return b.String()
}

func connector(i int) string {
	if i == 0 {
		return "●"
	}
	return "↳"
}

func badges(n ontology.Node) string {
	var out string
	if n.Bool(ontology.PropInternetExposed) {
		out += "  🌐 internet-exposed"
	}
	if n.Bool(ontology.PropCrownJewel) {
		out += "  💎 sensitive asset"
	}
	if sev, ok := n.Properties[ontology.PropSeverity].(string); ok && sev != "" {
		out += "  ⚠️ " + sev
	}
	return out
}
