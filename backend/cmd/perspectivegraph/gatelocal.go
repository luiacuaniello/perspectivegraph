package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	awsconnector "github.com/luiacuaniello/perspectivegraph/internal/connector/aws"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Local mode: answer the gate's question in the CI runner, with no deployment.
//
// The deployment is the reason the gate is hard to adopt - a tool that sells itself as
// shift-left should not require standing up Postgres, NATS and a webhook before it can
// say anything. So local mode reads the estate itself (read-only), ingests this pull
// request's scanner output, and computes the verdict in-process.
//
// What it is NOT: a way to answer without an estate. Without one there are no attack
// paths, only a flat list of findings - which is the thing this engine exists to replace.
// So an estate source is required, and "I could not read the estate" is an error, never
// a clean verdict.
//
// Everything downstream of the events is the SAME code the server runs - the same
// normalizer, the same pathfinder, the same triage priority. That is deliberate: local
// mode is a different way to obtain the graph, not a second engine with its own answers.

// reportSpec is one scanner report and the collector that parses it.
type reportSpec struct {
	source string
	path   string
}

// reportFlag collects repeatable -report values. Local mode needs several in one
// invocation - a repository usually has both a container scan and a SAST run, and with
// no server accumulating them, whatever this one process is given is the whole picture.
type reportFlag []reportSpec

func (r *reportFlag) String() string {
	out := make([]string, 0, len(*r))
	for _, s := range *r {
		out = append(out, s.source+"="+s.path)
	}
	return strings.Join(out, ",")
}

// Set accepts "source=path", or a bare "path" that inherits -source. The bare form keeps
// the single-report invocation identical to the server mode's.
func (r *reportFlag) Set(v string) error {
	if v == "" {
		return fmt.Errorf("empty -report")
	}
	if src, path, ok := strings.Cut(v, "="); ok {
		if src == "" || path == "" {
			return fmt.Errorf("-report %q: want source=path", v)
		}
		*r = append(*r, reportSpec{source: src, path: path})
		return nil
	}
	*r = append(*r, reportSpec{path: v})
	return nil
}

// resolveSources fills in the collector for bare -report values and rejects unknown ones
// up front, rather than after an AWS collection has already been paid for.
func (r reportFlag) resolveSources(defaultSource string) ([]reportSpec, error) {
	out := make([]reportSpec, 0, len(r))
	for _, s := range r {
		if s.source == "" {
			s.source = defaultSource
		}
		if _, ok := collectorFor(s.source); !ok {
			return nil, fmt.Errorf("no collector for source %q (have: %s)", s.source, strings.Join(collectorNames(), ", "))
		}
		out = append(out, s)
	}
	return out, nil
}

// localOpts is everything local mode needs to reach a verdict.
type localOpts struct {
	slug, sha  string
	pr         int
	repository string
	reports    []reportSpec
	estate     string // events JSON, as written by `awscollect -json`
	awsRegion  string
	awsRole    string

	// collectAWSFn is the live collection, swapped out in tests. Reaching the real SDK
	// is the one part of this pipeline a test cannot exercise, and the merge of the two
	// estate sources is precisely what must not regress.
	collectAWSFn func(context.Context) ([]ontology.Event, error)
}

// estate is what the environment sources produced, and how completely they managed it.
type estate struct {
	events []ontology.Event
	// partial is the reason the read was incomplete, empty when it was not. A gate that
	// downgrades this to a log line reports a clean build for an environment it never
	// saw, which is the failure this whole tool exists to make visible.
	partial string
}

// localMaxHops mirrors the server's ANALYZER_MAX_HOPS default. It is passed for
// signature fidelity with the analyzer service and bites nothing today: maxHops reaches
// only the DB-side Cypher pathfinder, and local mode runs on an in-memory store with the
// in-process Dijkstra. It is NOT exposed as a flag, because a knob that silently does
// nothing is worse than no knob.
const localMaxHops = 12

// localVerdict builds the graph in this process and returns the same verdict shape the
// server's prVerdict query returns, so every caller downstream - the printed report, the
// -json output, the action's outputs - cannot tell the two modes apart.
func localVerdict(ctx context.Context, o localOpts) (gateVerdict, error) {
	store := memory.New()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return store, nil })
	if err != nil {
		return gateVerdict{}, err
	}
	// The production normalizer: identity resolution, crown-jewel inference, threat-intel
	// hooks. Applying events straight to the store would skip all of it and quietly build
	// a different graph than the server builds from the same input.
	norm := normalization.New(mgr)

	est, err := o.collectEstate(ctx)
	if err != nil {
		return gateVerdict{}, err
	}
	if len(est.events) == 0 {
		return gateVerdict{}, fmt.Errorf("the estate source produced no events, so there is nothing for this commit to be reachable through")
	}

	reports, err := o.parseReports()
	if err != nil {
		return gateVerdict{}, err
	}

	if err := applyEvents(ctx, norm, append(reports, est.events...)); err != nil {
		return gateVerdict{}, err
	}

	snap, err := store.Snapshot(ctx)
	if err != nil {
		return gateVerdict{}, err
	}
	// Exactly what the analyzer service does per pass, in the same order. Prioritize is
	// NOT part of the pathfinder: leaving it out would return the paths unranked and with
	// a zero priority, so the gate would report a different order - and a different "top"
	// path - than the dashboard shows for the same estate.
	paths := analyzer.CriticalPathsVia(ctx, store, snap, localMaxHops, false)
	analyzer.Prioritize(paths)

	v := buildVerdict(snap, paths, o.slug, o.sha)
	v.Incomplete = est.partial
	return v, nil
}

// buildVerdict applies the same three-state rule as the prVerdict resolver: "analysed" is
// answered from the GRAPH, not from the paths, so an asset that exists and reaches
// nothing reads as clean rather than as never-seen.
func buildVerdict(snap graph.Snapshot, paths []analyzer.AttackPath, slug, sha string) gateVerdict {
	v := gateVerdict{AnalysedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	for _, n := range snap.Nodes {
		if ontology.StampedWith(n.Properties, slug, sha) {
			v.Analysed = true
			break
		}
	}
	for _, p := range paths {
		for _, n := range p.Nodes {
			if !ontology.StampedWith(n.Properties, slug, sha) {
				continue
			}
			hop := gatePath{ID: p.ID, Score: p.Score, Priority: p.Priority}
			for _, pn := range p.Nodes {
				hop.Nodes = append(hop.Nodes, gateNode{Name: pn.Name, Label: string(pn.Label)})
			}
			v.Paths = append(v.Paths, hop)
			break
		}
	}
	v.CriticalPaths = len(v.Paths)
	return v
}

// collectEstate reads the environment the change will land in. Every source is read-only;
// none of them writes anything to the account.
//
// Sources ADD UP rather than override. Almost nobody's estate is one cloud region: the
// file is the escape hatch for whatever the connector cannot read - another provider,
// on-prem, the CI provenance linking an image to where it runs. Letting one silently win
// would drop half the environment and answer confidently about the remainder, which for
// a reachability question means reporting clean because the route left the part it read.
func (o localOpts) collectEstate(ctx context.Context) (estate, error) {
	if o.estate == "" && o.awsRegion == "" && o.collectAWSFn == nil {
		return estate{}, fmt.Errorf("local mode needs an estate: pass -aws-region (live, read-only) or -estate <events.json>")
	}
	var out estate

	if o.estate != "" {
		b, err := os.ReadFile(o.estate) // #nosec G304 G703 -- operator-supplied path to their own estate export
		if err != nil {
			return estate{}, fmt.Errorf("read -estate: %w", err)
		}
		var fromFile []ontology.Event
		if err := json.Unmarshal(b, &fromFile); err != nil {
			return estate{}, fmt.Errorf("decode -estate (expects the JSON `awscollect -json` writes): %w", err)
		}
		out.events = append(out.events, fromFile...)
	}

	if o.awsRegion != "" || o.collectAWSFn != nil {
		collect := o.collectAWS
		if o.collectAWSFn != nil {
			collect = o.collectAWSFn
		}
		live, partial, err := collect2(ctx, collect)
		if err != nil {
			return estate{}, err
		}
		out.events = append(out.events, live...)
		out.partial = partial
	}
	return out, nil
}

// collect2 separates the two ways a live read goes wrong, which the first version of this
// conflated into one warning. Reading NOTHING is a failure - bad credentials, a wrong
// region, a denied role - and continuing on whatever an -estate file happened to contain
// would grade the commit against an environment nobody looked at. Reading only PART of it
// is survivable, but it has to travel with the verdict rather than scroll past in a log.
func collect2(ctx context.Context, collect func(context.Context) ([]ontology.Event, error)) ([]ontology.Event, string, error) {
	events, err := collect(ctx)
	if err == nil {
		return events, "", nil
	}
	if len(events) == 0 {
		return nil, "", fmt.Errorf("could not read the estate at all, so there is nothing to judge this commit against: %w", err)
	}
	return events, err.Error(), nil
}

// collectAWS reads the live account: describes and lists only, no writes, no cost.
func (o localOpts) collectAWS(ctx context.Context) ([]ontology.Event, error) {
	conn, err := awsconnector.NewFromConfig(ctx, awsconnector.Config{
		Mode: "sdk", Region: o.awsRegion, RoleARN: o.awsRole,
	})
	if err != nil {
		return nil, fmt.Errorf("aws connector: %w", err)
	}
	// Collect joins per-feed errors and still returns what it did read, so the error and
	// the events both matter. Grading how bad it is belongs to the caller.
	return conn.Collect(ctx)
}

// parseReports turns this pull request's scanner output into events, stamped with the
// commit. The stamp is what makes the change findable in the graph afterwards; without
// it every verdict here would be UNKNOWN.
func (o localOpts) parseReports() ([]ontology.Event, error) {
	opts := ingestion.Options{
		Repository: o.repository,
		RepoSlug:   o.slug,
		CommitSHA:  o.sha,
		PRNumber:   o.pr,
	}
	var out []ontology.Event
	for _, spec := range o.reports {
		c, ok := collectorFor(spec.source)
		if !ok {
			return nil, fmt.Errorf("no collector for source %q", spec.source)
		}
		f, err := os.Open(spec.path) // #nosec G304 G703 -- operator-supplied path to their own scanner output
		if err != nil {
			return nil, fmt.Errorf("open -report %s: %w", spec.path, err)
		}
		events, err := c.Parse(f, opts)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s report %s: %w", spec.source, spec.path, err)
		}
		out = append(out, events...)
	}
	return out, nil
}

// danglingEdge reports whether the store refused an edge because it has not seen an
// endpoint yet - a forward reference, not a broken graph.
func danglingEdge(err error) bool {
	return err != nil && strings.Contains(err.Error(), "endpoint node(s) not in graph yet")
}

// applyEvents feeds every event through the normalizer, independently of the order they
// arrive in.
//
// Order matters to the store, which refuses an edge whose endpoints it has not seen, and
// forward references are normal here rather than exceptional: a scanner report introduces
// the image, the cloud connector describes the roles, and an operator's supplement links
// the two - so whichever runs first points at something that does not exist yet. Making
// that the caller's problem would mean publishing an ordering rule and letting anyone who
// gets it wrong watch the run die on an edge.
//
// So events that only await an endpoint are retried, and the pass repeats while it keeps
// making progress. What survives that is a genuine dangling reference: something in the
// estate points at an asset nothing described, and no ordering would have saved it. That
// is an error rather than a dropped edge, because the edge that gets dropped is exactly
// the one that made the commit reachable - and losing it reports a clean build.
func applyEvents(ctx context.Context, norm *normalization.Normalizer, events []ontology.Event) error {
	pending := events
	for {
		var deferred []ontology.Event
		for _, ev := range pending {
			err := norm.Handle(ctx, ev)
			switch {
			case err == nil:
			case danglingEdge(err):
				deferred = append(deferred, ev)
			default:
				return fmt.Errorf("apply event: %w", err)
			}
		}
		if len(deferred) == 0 {
			return nil
		}
		// No progress this pass means the missing endpoints are never coming.
		if len(deferred) == len(pending) {
			if err := norm.Handle(ctx, deferred[0]); err != nil {
				return fmt.Errorf(
					"the estate refers to an asset that nothing else described, so the graph cannot be "+
						"completed (pass the missing scan with -report/-reports, or drop the reference): %w", err)
			}
			return nil
		}
		pending = deferred
	}
}
