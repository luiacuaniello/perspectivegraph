package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	awsconnector "github.com/luiacuaniello/perspectivegraph/internal/connector/aws"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
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

// drainStdinReport reads the report a "-" asks for, and does it first.
//
// An output plugin - `trivy image -f json -o plugin=perspectivegraph` - hands the report
// over stdin and waits for it to be taken. A process that exits before reading it, on a
// missing -sha or an unreadable estate or anything else, leaves the writer blocked:
// measured, Trivy 0.71 then hangs indefinitely instead of failing, and the pipeline
// stalls with the real error buried in its log. So stdin is drained before anything in
// the gate can fail. It is one stream, so only one report can come from it.
func drainStdinReport(stdin io.Reader, single string, many reportFlag) ([]byte, error) {
	n := 0
	if single == "-" {
		n++
	}
	for _, s := range many {
		if s.path == "-" {
			n++
		}
	}
	if n == 0 {
		return nil, nil
	}
	// Read even when the invocation is about to be refused: the refusal is exactly the
	// early exit that would otherwise leave the writer hanging.
	b, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("read -report from stdin: %w", err)
	}
	if n > 1 {
		return nil, errors.New("only one report can come from stdin (-report -)")
	}
	return b, nil
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
	// baseReports are scans of what runs now - the base branch - applied to the estate,
	// unstamped, before the comparison (diff attribution).
	baseReports []reportSpec
	// attribution is "diff" (the default: the routes the reports open or worsen) or
	// "commit" (every route through an asset stamped with the commit).
	attribution string
	estate      string // events JSON, as written by `awscollect -json`
	// account is the AWS account the reports describe, for those whose identifiers are
	// unique only within one (a plan's instances); empty, the report's own say.
	account string
	// estateKnown is set once an estate has been read: a change report then leaves to it
	// what it cannot judge better (ingestion.Options.EstateKnown); estateAccount is the
	// account it was read from, for a change report that names none.
	estateKnown   bool
	estateAccount string
	awsRegion     string
	awsRole       string
	// cluster names the Kubernetes cluster this change's reports describe (see
	// ingestion.Options.Cluster), so they meet the estate's objects of that cluster.
	cluster string
	// stdin is the report read from standard input, for a -report of "-". It is read by
	// the caller before anything else, for the reason drainStdinReport gives.
	stdin []byte

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

	// A plan describes the estate it changes - the part its configuration manages - so it
	// can be judged on its own. Without a live read, a route through what the
	// configuration does not manage is not seen; with one, it is.
	change := false
	for _, spec := range o.reports {
		if c, ok := collectorFor(spec.source); ok {
			_, isChange := c.(ingestion.ChangeParser)
			change = change || isChange
		}
	}
	planOnly := change && o.estate == "" && o.awsRegion == "" && o.collectAWSFn == nil
	var est estate
	if !planOnly {
		if est, err = o.collectEstate(ctx); err != nil {
			return gateVerdict{}, err
		}
		if len(est.events) == 0 {
			return gateVerdict{}, fmt.Errorf("the estate source produced no events, so there is nothing for this commit to be reachable through")
		}
		// A plan of new resources names no account; the account the estate was read from
		// is the one it lands in.
		o.estateAccount = estateAccount(est.events)
		o.estateKnown = true
	}
	reports, err := o.parseReports(o.reports, true)
	if err != nil {
		return gateVerdict{}, err
	}
	est.events = append(est.events, reports.before...)

	if o.attribution != "commit" {
		return o.diffVerdict(ctx, norm, store, est, reports)
	}

	if err := applyEvents(ctx, norm, store, append(reports.events, est.events...)); err != nil {
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
	v.Attribution = "commit"
	v.Incomplete = joinReasons(est.partial, impact.UnknownReason(reports.unknown))
	return v, nil
}

// estateAccount is the account most of the estate's assets say they belong to, or "".
func estateAccount(events []ontology.Event) string {
	counts := map[string]int{}
	for _, ev := range events {
		for _, n := range ev.Nodes {
			if a, _ := n.Properties[ontology.PropAccount].(string); a != "" {
				counts[a]++
			}
		}
	}
	best, most := "", 0
	for a, n := range counts {
		if n > most || (n == most && a < best) {
			best, most = a, n
		}
	}
	return best
}

// joinReasons puts together the reasons a verdict is incomplete.
func joinReasons(reasons ...string) string {
	var out []string
	for _, r := range reasons {
		if r != "" {
			out = append(out, r)
		}
	}
	return strings.Join(out, "; ")
}

// diffVerdict is local mode's comparison, the same one a server runs (package impact):
// the estate - with the scans of what runs now, when given - against the estate with
// this change's reports applied.
func (o localOpts) diffVerdict(ctx context.Context, norm *normalization.Normalizer, store *memory.Store, est estate, reports parsedReports) (gateVerdict, error) {
	base, err := o.parseReports(o.baseReports, false)
	if err != nil {
		return gateVerdict{}, err
	}
	for _, ev := range append(est.events, base.events...) {
		if err := norm.Handle(ctx, ev); err != nil && !errors.Is(err, graph.ErrEndpointsMissing) {
			return gateVerdict{}, fmt.Errorf("apply event: %w", err)
		}
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		return gateVerdict{}, err
	}
	// The estate's links to assets only the change describes wait in the store; they go
	// into the comparison with it, or the change's image would look unreachable.
	pending, _, err := store.PendingEdges(ctx, -1)
	if err != nil {
		return gateVerdict{}, err
	}
	res, err := impact.Evaluate(ctx, impact.Input{
		Base: snap, BasePending: pending, Change: reports.events, Unknown: reports.unknown, Slug: o.slug, SHA: o.sha,
	})
	if err != nil {
		return gateVerdict{}, err
	}
	// What still waits once the change is in is a reference nothing describes, and the
	// edge that gets dropped may be exactly the one that made the change reachable: an
	// error, as it always was here, never a clean verdict.
	if res.Waiting > 0 {
		e := res.Sample
		return gateVerdict{}, fmt.Errorf(
			"the estate refers to an asset that nothing else described, so the graph cannot be "+
				"completed (pass the missing scan with -report/-reports/-base-reports, or drop the reference): "+
				"%d edge(s) wait for an endpoint, e.g. %s %s->%s: %w", res.Waiting, e.Type, e.From, e.To, graph.ErrEndpointsMissing)
	}
	v := verdictFromImpact(res)
	v.Incomplete = joinReasons(est.partial, res.Incomplete)
	return v, nil
}

// verdictFromImpact renders a comparison as the gate's verdict, the shape POST
// /gate/impact answers with.
func verdictFromImpact(res impact.Result) gateVerdict {
	v := gateVerdict{
		Attribution: "diff",
		Analysed:    res.Analysed,
		AnalysedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		Preexisting: res.Preexisting,
		Recorded:    res.Recorded,
		Reachable:   res.Reachable,
	}
	for _, p := range res.Blocking {
		gp := gatePath{ID: p.ID, Score: p.Score, Priority: p.Priority, Change: string(p.Change), PreviousScore: p.PreviousScore}
		for _, n := range p.Nodes {
			gp.Nodes = append(gp.Nodes, gateNode{Name: n.Name, Label: string(n.Label)})
		}
		v.Paths = append(v.Paths, gp)
	}
	v.CriticalPaths = len(v.Paths)
	return v
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

// parseReports turns scanner output into events. This pull request's are stamped with the
// commit: the stamp is what makes the change findable in the graph afterwards, and
// without it every verdict here would be UNKNOWN. The base branch's are not - they are
// what runs now, not the change.
//
// A change report - a Terraform plan - also says what state it starts from (Before), which
// joins the estate, and what it leaves unknown until it is applied.
func (o localOpts) parseReports(specs []reportSpec, stamped bool) (parsedReports, error) {
	opts := ingestion.Options{Repository: o.repository, Cluster: o.cluster, Account: o.account, EstateKnown: o.estateKnown}
	if stamped {
		opts.RepoSlug, opts.CommitSHA, opts.PRNumber = o.slug, o.sha, o.pr
	}
	var out parsedReports
	for _, spec := range specs {
		c, ok := collectorFor(spec.source)
		if !ok {
			return parsedReports{}, fmt.Errorf("no collector for source %q", spec.source)
		}
		var r io.Reader
		if spec.path == "-" {
			r = bytes.NewReader(o.stdin)
		} else {
			f, openErr := os.Open(spec.path) // #nosec G304 G703 -- operator-supplied path to their own scanner output
			if openErr != nil {
				return parsedReports{}, fmt.Errorf("open -report %s: %w", spec.path, openErr)
			}
			defer func() { _ = f.Close() }()
			r = f
		}
		var ch ingestion.Change
		var err error
		if cp, isChange := c.(ingestion.ChangeParser); isChange && stamped {
			copts := opts
			if copts.Account == "" {
				copts.Account = o.estateAccount
			}
			ch, err = cp.ParseChange(r, copts)
			out.change = true
		} else {
			ch.After, err = c.Parse(r, opts)
		}
		if err != nil {
			return parsedReports{}, fmt.Errorf("parse %s report %s: %w", spec.source, spec.path, err)
		}
		out.events = append(out.events, ch.After...)
		out.before = append(out.before, ch.Before...)
		out.unknown = append(out.unknown, ch.Unknown...)
	}
	return out, nil
}

// parsedReports are reports turned into events.
type parsedReports struct {
	events []ontology.Event
	// before is the state change reports start from; unknown, what they leave unknown
	// until applied; change, whether there was a change report at all.
	before  []ontology.Event
	unknown []string
	change  bool
}

// applyEvents feeds every event through the normalizer, independently of the order they
// arrive in.
//
// Forward references are normal here rather than exceptional: a scanner report
// introduces the image, the cloud connector describes the roles, and an operator's
// supplement links the two - so whichever runs first points at something that does not
// exist yet. The store parks such an edge and lands it when its endpoint arrives
// (graph.EdgeParker), so the order does not matter and one pass is enough.
//
// What is still parked afterwards is a genuine dangling reference: something in the
// estate points at an asset nothing described, and no ordering would have saved it. That
// is an error rather than a dropped edge, because the edge that gets dropped is exactly
// the one that made the commit reachable - and losing it reports a clean build.
func applyEvents(ctx context.Context, norm *normalization.Normalizer, store graph.EdgeParker, events []ontology.Event) error {
	for _, ev := range events {
		if err := norm.Handle(ctx, ev); err != nil {
			return fmt.Errorf("apply event: %w", err)
		}
	}
	waiting, n, err := store.PendingEdges(ctx, 1)
	if err != nil {
		return err
	}
	if n > 0 {
		e := waiting[0]
		return fmt.Errorf(
			"the estate refers to an asset that nothing else described, so the graph cannot be "+
				"completed (pass the missing scan with -report/-reports, or drop the reference): "+
				"%d edge(s) wait for an endpoint, e.g. %s %s->%s: %w", n, e.Type, e.From, e.To, graph.ErrEndpointsMissing)
	}
	return nil
}
