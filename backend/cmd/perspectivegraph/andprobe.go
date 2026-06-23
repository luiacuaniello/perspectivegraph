package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// runAndProbe is the #6 (Bayesian Attack Graph) DECISION tool: does your environment
// actually have attack steps with AND semantics (a compromise requiring several
// distinct prerequisites at once), or is it pure OR-reachability (which the Monte
// Carlo already models)? It scans the live graph and counts, on critical paths, the
// nodes whose incoming edges span >= 2 distinct prerequisite categories (network /
// vulnerability / identity / escape) - the places where the current OR assumption
// MIGHT be wrong and a BAG could add signal.
//
//	perspectivegraph andprobe --api http://localhost:8080
//
// HONESTY: this is an *upper-bound heuristic*. A pure attack graph cannot tell AND
// from OR structurally - that is precisely what a BAG adds - so many flagged nodes
// are really OR (multiple independent entry points). The number bounds the question
// and names the candidates; the GROUND TRUTH is your real `refuted` verdicts: a
// refuted path that in reality needed an extra, missing precondition is a confirmed
// AND node. Use this to decide whether #6 is worth building, not as proof it is.
func runAndProbe(args []string) error {
	fs := flag.NewFlagSet("andprobe", flag.ContinueOnError)
	api := fs.String("api", "http://localhost:8080", "API base URL")
	token := fs.String("token", os.Getenv("API_TOKEN"), "bearer token, if API auth is on")
	top := fs.Int("top", 10, "how many candidate nodes to list")
	allNodes := fs.Bool("all-nodes", false, "analyze every graph node (topology exploration), not just critical-path nodes (the #6 decision)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	q := []byte(`{"query":"{ attackPaths { nodes { id name label } } graph { edges { type from to } nodes { id name label } } }"}`)
	st, rb, err := apiRequest(client, http.MethodPost, *api+"/graphql", *token, q)
	if err != nil {
		return err
	}
	if st >= 300 {
		return fmt.Errorf("graphql returned %d: %s", st, string(rb))
	}
	var resp struct {
		Data struct {
			AttackPaths []struct {
				Nodes []probeNode `json:"nodes"`
			} `json:"attackPaths"`
			Graph struct {
				Edges []struct {
					Type, From, To string
				} `json:"edges"`
				Nodes []probeNode `json:"nodes"`
			} `json:"graph"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rb, &resp); err != nil {
		return err
	}
	if !*allNodes && len(resp.Data.AttackPaths) == 0 {
		return fmt.Errorf("no attack paths surfaced yet (seed the graph, or use --all-nodes to inspect the whole topology)")
	}

	info := map[string]probeNode{}
	for _, n := range resp.Data.Graph.Nodes {
		info[n.ID] = n
	}
	// Incoming prerequisite categories per node (from the whole graph), plus the raw
	// edge types feeding it (for display).
	cats := map[string]map[string]bool{}
	etypes := map[string]map[string]bool{}
	for _, e := range resp.Data.Graph.Edges {
		c := edgeCategory[e.Type]
		if c == "" {
			continue
		}
		if cats[e.To] == nil {
			cats[e.To] = map[string]bool{}
			etypes[e.To] = map[string]bool{}
		}
		cats[e.To][c] = true
		etypes[e.To][e.Type] = true
	}

	// The node set to judge: every graph node (--all-nodes, topology exploration) or
	// just the nodes reached after a seed on a critical path (the #6 decision).
	targets := map[string]bool{}
	if *allNodes {
		for _, n := range resp.Data.Graph.Nodes {
			targets[n.ID] = true
		}
	} else {
		for _, p := range resp.Data.AttackPaths {
			for i := 1; i < len(p.Nodes); i++ {
				targets[p.Nodes[i].ID] = true
			}
		}
	}

	pathsThrough := 0
	for _, p := range resp.Data.AttackPaths {
		for i := 1; i < len(p.Nodes); i++ {
			if len(cats[p.Nodes[i].ID]) >= 2 {
				pathsThrough++
				break
			}
		}
	}

	var candidates []string
	for id := range targets {
		if len(cats[id]) >= 2 {
			candidates = append(candidates, id)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if len(cats[candidates[i]]) != len(cats[candidates[j]]) {
			return len(cats[candidates[i]]) > len(cats[candidates[j]])
		}
		return info[candidates[i]].Name < info[candidates[j]].Name
	})

	nPaths := len(resp.Data.AttackPaths)
	frac := 0.0
	if nPaths > 0 {
		frac = float64(pathsThrough) / float64(nPaths)
	}
	scope := "critical-path"
	if *allNodes {
		scope = "all-graph"
	}

	fmt.Printf("andprobe [%s]: %d nodes analyzed (%d critical paths in the graph)\n", scope, len(targets), nPaths)
	fmt.Printf("  AND-candidate nodes (>=2 distinct incoming prerequisite categories): %d\n", len(candidates))
	if !*allNodes {
		fmt.Printf("  critical paths through an AND candidate: %d/%d (%.0f%%)\n", pathsThrough, nPaths, frac*100)
		fmt.Printf("  verdict: %s\n", andVerdict(frac, len(candidates)))
	}
	if len(candidates) > 0 {
		fmt.Printf("  --- top candidates (a human/verdict must confirm each is really AND, not just multiple OR entry points) ---\n")
		for i, id := range candidates {
			if i >= *top {
				break
			}
			fmt.Printf("    %-34s [%s]  needs: %s  (edges: %s)\n",
				trunc(info[id].Name, 34), info[id].Label, joinSet(cats[id]), joinSet(etypes[id]))
		}
	}
	fmt.Printf("  NOTE: upper-bound heuristic - a pure graph can't tell AND from OR. Confirm with real\n")
	fmt.Printf("        `refuted` verdicts: a path refuted because a precondition was missing = a true AND node.\n")
	return nil
}

type probeNode struct {
	ID, Name, Label string
}

// edgeCategory maps an edge type to the kind of attacker prerequisite it represents.
// A node fed by >= 2 distinct categories is a place where "reachable via OR" might
// really be "requires all of these (AND)".
var edgeCategory = map[string]string{
	"HOSTS": "network", "CONNECTS_TO": "network", "EXPOSES": "network", "ROUTES_TO": "network",
	"DEPENDS_ON": "vulnerability", "COMPILED_INTO": "vulnerability", "BUILT_FROM": "vulnerability",
	"AFFECTS": "vulnerability", "EXPLOITS": "vulnerability",
	"ASSUMES": "identity", "HAS_PERMISSION": "identity", "CAN_ESCALATE_TO": "identity", "AUTHENTICATES": "identity",
	"ESCAPES_TO": "escape",
}

func andVerdict(frac float64, candidates int) string {
	switch {
	case candidates == 0 || frac < 0.1:
		return "or-dominated - #6 BAG is likely a NO-OP here; invest in better p(e) (calibration, κ-from-evidence-counts) instead"
	case frac < 0.4:
		return "some AND candidates - #6 may add signal on a minority of paths; confirm with real refuted verdicts before building"
	default:
		return "AND semantics is common - #6 BAG (as Monte-Carlo-over-BAG) would likely add real signal; still confirm with verdicts"
	}
}

func joinSet(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
