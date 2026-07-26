package redteam

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	pgiam "github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
)

// AWSOracle settles assertions against AWS itself - the only authority independent of
// the engine's own beliefs.
//
// It uses `iam:SimulatePrincipalPolicy`, AWS's own policy evaluator, which is a
// DRY RUN: it answers "would this be allowed" without performing anything, costs
// nothing, and needs no vulnerable infrastructure. That matters beyond convenience -
// it means the calibration evidence can be gathered against a real account without
// standing up something exploitable.
//
// Crucially it evaluates what the engine does not: SCPs and condition keys both
// participate in the simulation. So a principal the engine reports as escalating, but
// that reality actually stops, comes back DENIED - which is exactly the refuted
// verdict the calibration flywheel has no other honest way to obtain. Permissions
// boundaries used to be on that list, and the refutation this oracle produced for one
// is why the engine now evaluates them itself.
//
// Network claims still need an in-VPC probe host, which this does not stand up, and
// exploit claims need a real exploit. Both stay Inconclusive rather than guessed.
type AWSOracle struct {
	iam simulator

	// memo caches one answer per assertion key. Many paths converge on the same
	// principal - an over-permissioned shared role is exactly the thing that generates
	// dozens of paths - and reality's answer does not depend on which path prompted the
	// question. Without this, an audit of a hundred paths would make a hundred identical
	// simulations and invite throttling.
	mu   sync.Mutex
	memo map[string]Result
}

// simulator is the one IAM call this oracle makes, as an interface so the whole
// decision path is testable without an AWS account.
type simulator interface {
	SimulatePrincipalPolicy(context.Context, *iam.SimulatePrincipalPolicyInput, ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// NewAWSOracle builds the oracle over an IAM client.
func NewAWSOracle(client simulator) *AWSOracle { return &AWSOracle{iam: client} }

// NewAWSOracleFromConfig builds one from the ambient AWS credential chain (env,
// profile, IRSA, instance role), optionally assuming a read-only role first. The
// caller needs `iam:SimulatePrincipalPolicy`; nothing here writes.
func NewAWSOracleFromConfig(ctx context.Context, region, roleARN string) (*AWSOracle, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	if roleARN != "" {
		cfg.Credentials = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), roleARN)
	}
	return &AWSOracle{iam: iam.NewFromConfig(cfg)}, nil
}

// Check settles one assertion. Anything it cannot decide comes back Inconclusive,
// never Denied: a refutation has to mean "reality said no", not "we failed to ask".
func (o *AWSOracle) Check(ctx context.Context, a Assertion) (Result, error) {
	if o == nil || o.iam == nil {
		return Result{Decision: Inconclusive, Evidence: "aws oracle not configured"}, nil
	}
	if a.Kind != KindIAM || !a.Testable {
		return Result{Decision: Inconclusive, Evidence: "not settleable by the IAM oracle: " + a.Note}, nil
	}

	key := a.Key()
	o.mu.Lock()
	cached, hit := o.memo[key]
	o.mu.Unlock()
	if hit {
		return cached, nil
	}

	var res Result
	var err error
	if a.Action == escalationAction {
		res, err = o.checkEscalation(ctx, a)
	} else {
		res, err = o.checkAction(ctx, a)
	}
	if err != nil {
		return res, err
	}

	// Inconclusive results are not cached: they usually mean a transient failure
	// (throttling, a timeout), and caching one would make a blip permanent.
	if res.Decision != Inconclusive {
		o.mu.Lock()
		if o.memo == nil {
			o.memo = map[string]Result{}
		}
		o.memo[key] = res
		o.mu.Unlock()
	}
	return res, nil
}

// checkAction settles a single concrete action, scoped to the target resource when
// the assertion names one (an ARN; a graph id would be meaningless to AWS).
func (o *AWSOracle) checkAction(ctx context.Context, a Assertion) (Result, error) {
	in := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: &a.Principal,
		ActionNames:     []string{a.Action},
	}
	if strings.HasPrefix(a.Resource, "arn:") {
		in.ResourceArns = []string{a.Resource}
	}
	evals, err := o.simulate(ctx, in)
	if err != nil {
		return Result{Decision: Inconclusive, Evidence: err.Error()}, nil
	}
	e := evals[a.Action]
	switch {
	case e.allowed():
		return Result{Decision: Allowed, Evidence: "SimulatePrincipalPolicy: " + a.Action + " allowed"}, nil
	case e.conditional():
		return Result{Decision: Inconclusive,
			Evidence: fmt.Sprintf("SimulatePrincipalPolicy: %s turns on request context not supplied (%s), so neither permitted nor refused",
				a.Action, strings.Join(e.missing, ", "))}, nil
	default:
		return Result{Decision: Denied,
			Evidence: fmt.Sprintf("SimulatePrincipalPolicy: %s %s", a.Action, orUnknown(e.decision))}, nil
	}
}

// checkEscalation settles "this principal holds SOME privilege-escalation primitive".
//
// It never asks AWS about `iam:*`: AWS reads that as "may perform EVERY IAM action",
// so a principal holding one genuine privesc permission would come back denied and
// produce a false refutation. Instead every primitive's concrete actions are
// simulated in one call, and the claim holds if any single primitive has ALL of its
// actions allowed - the same all-of rule the detector applies.
//
// The simulation is not resource-scoped, matching the engine's own detection: both
// ask whether the permission is held at all. A permission held only on harmless
// resources is therefore reported allowed by both, and the engine already grades that
// case down separately (resource_scoped).
func (o *AWSOracle) checkEscalation(ctx context.Context, a Assertion) (Result, error) {
	prims := pgiam.PrivescPrimitives()

	seen := map[string]bool{}
	var actions []string
	for _, p := range prims {
		for _, act := range p.Actions {
			if !seen[act] {
				seen[act] = true
				actions = append(actions, act)
			}
		}
	}
	sort.Strings(actions) // deterministic request, so evidence is reproducible

	in := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: &a.Principal,
		ActionNames:     actions,
	}
	// Naming a resource narrows the question from "account-wide" to "over this thing".
	// AWS evaluates an unnamed resource as `*`, so without this a grant confined to
	// specific resources is invisible - see the denial evidence below.
	scope := "account-wide"
	if strings.HasPrefix(a.Resource, "arn:") {
		in.ResourceArns = []string{a.Resource}
		scope = "over " + a.Resource
	}

	evals, err := o.simulate(ctx, in)
	if err != nil {
		return Result{Decision: Inconclusive, Evidence: err.Error()}, nil
	}

	// Collect every primitive that holds outright. An unconditional grant is reported
	// cleanly even when other statements on the principal carry Conditions - verified
	// against the real API - so a genuine permit is never lost to the guard below.
	var holding []string
	for _, p := range prims {
		if len(p.Actions) == 0 {
			continue
		}
		holds := true
		for _, act := range p.Actions {
			if !evals[act].allowed() {
				holds = false
				break
			}
		}
		if holds {
			holding = append(holding, p.Name)
		}
	}
	if len(holding) > 0 {
		return Result{Decision: Allowed,
			Evidence: fmt.Sprintf("SimulatePrincipalPolicy: holds %s (%s)", strings.Join(holding, "; "), scope)}, nil
	}

	// Nothing held outright. Before calling that a refutation, check whether AWS could
	// actually evaluate the question: when a Condition applies and the simulation was
	// given no value for its key, AWS answers `implicitDeny` AND reports the key in
	// MissingContextValues. Reading only the decision turns "I could not evaluate this"
	// into "reality refuses" - a fabricated refutation, and if the condition were an
	// `aws:SourceIp` the attacker actually matches, the engine's claim would have been
	// right all along.
	//
	// The keys cannot be attributed to particular primitives: AWS reports them on every
	// action in the simulation, including actions the policies never grant, so
	// "not granted at all" and "granted under a condition" are indistinguishable here.
	// Naming which primitives are gated would be a guess, so this names only the keys.
	missingKeys := map[string]bool{}
	for _, act := range actions {
		for _, k := range evals[act].missing {
			missingKeys[k] = true
		}
	}
	if len(missingKeys) > 0 {
		return Result{Decision: Inconclusive,
			Evidence: fmt.Sprintf("SimulatePrincipalPolicy: cannot settle - this principal's policies turn on request context the simulation was not given (%s), so AWS's implicitDeny means \"unevaluated\", not \"refused\". The engine reads an Allow as unconditional and claims the escalation; whether reality grants it depends on whether the attacker satisfies the condition.",
				namedKeys(missingKeys))}, nil
	}

	// Be precise about what was established. With no resource named, AWS evaluated the
	// question against `*`, so this refutes an ACCOUNT-WIDE escalation and nothing more:
	// a grant confined to specific resources answers implicitDeny here and is
	// indistinguishable from holding no grant at all. The engine does surface those,
	// scored down as `resource_scoped`, so settling one means re-asking with the
	// resource named (EscalationClaimOn).
	if scope == "account-wide" {
		return Result{Decision: Denied,
			Evidence: fmt.Sprintf("SimulatePrincipalPolicy: no escalation primitive is permitted account-wide (%d actions evaluated over `*`). A grant scoped to specific resources would not appear here - name the resource to settle one.",
				len(actions))}, nil
	}
	return Result{Decision: Denied,
		Evidence: fmt.Sprintf("SimulatePrincipalPolicy: no escalation primitive is permitted %s (%d actions evaluated)",
			scope, len(actions))}, nil
}

// evaluation is one action's simulated outcome, plus the request-context keys the
// policy's Condition blocks needed and the simulation could not supply.
type evaluation struct {
	decision string
	// missing are the condition keys AWS reported as MissingContextValues. When this is
	// non-empty the decision is NOT a finding: AWS is saying "a Condition applies and I
	// was not given the value", which reads as implicitDeny but means "unknown".
	missing []string
}

// allowed reports a conclusive permit: allowed, with no unevaluated Condition.
func (e evaluation) allowed() bool {
	return e.decision == string(iamtypes.PolicyEvaluationDecisionTypeAllowed) && len(e.missing) == 0
}

// conditional reports that the outcome turns on request context the simulation lacked,
// so it is neither a permit nor a refusal.
func (e evaluation) conditional() bool { return len(e.missing) > 0 }

// simulate runs one simulation and flattens it to action -> evaluation.
func (o *AWSOracle) simulate(ctx context.Context, in *iam.SimulatePrincipalPolicyInput) (map[string]evaluation, error) {
	out, err := o.iam.SimulatePrincipalPolicy(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("SimulatePrincipalPolicy failed: %w", err)
	}
	evals := make(map[string]evaluation, len(out.EvaluationResults))
	for _, r := range out.EvaluationResults {
		if r.EvalActionName != nil {
			evals[*r.EvalActionName] = evaluation{
				decision: string(r.EvalDecision),
				missing:  append([]string(nil), r.MissingContextValues...),
			}
		}
	}
	return evals, nil
}

// namedKeys renders a deduplicated, ordered key list for evidence.
func namedKeys(keys map[string]bool) string {
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func orUnknown(s string) string {
	if s == "" {
		return "no decision returned"
	}
	return s
}
