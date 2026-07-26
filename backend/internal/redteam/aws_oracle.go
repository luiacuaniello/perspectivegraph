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
	decisions, err := o.simulate(ctx, in)
	if err != nil {
		return Result{Decision: Inconclusive, Evidence: err.Error()}, nil
	}
	if decisions[a.Action] == string(iamtypes.PolicyEvaluationDecisionTypeAllowed) {
		return Result{Decision: Allowed, Evidence: "SimulatePrincipalPolicy: " + a.Action + " allowed"}, nil
	}
	return Result{Decision: Denied,
		Evidence: fmt.Sprintf("SimulatePrincipalPolicy: %s %s", a.Action, orUnknown(decisions[a.Action]))}, nil
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

	decisions, err := o.simulate(ctx, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: &a.Principal,
		ActionNames:     actions,
	})
	if err != nil {
		return Result{Decision: Inconclusive, Evidence: err.Error()}, nil
	}

	allowed := func(act string) bool {
		return decisions[act] == string(iamtypes.PolicyEvaluationDecisionTypeAllowed)
	}
	// Collect every primitive that holds, not just the first: which ones they are is
	// the actionable part of the finding, and it costs nothing once the decisions are in.
	var holding []string
	for _, p := range prims {
		holds := len(p.Actions) > 0
		for _, act := range p.Actions {
			if !allowed(act) {
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
			Evidence: fmt.Sprintf("SimulatePrincipalPolicy: holds %s", strings.Join(holding, "; "))}, nil
	}
	return Result{Decision: Denied,
		Evidence: fmt.Sprintf("SimulatePrincipalPolicy: none of the %d escalation primitives are permitted (%d actions evaluated)",
			len(prims), len(actions))}, nil
}

// simulate runs one simulation and flattens it to action -> decision.
func (o *AWSOracle) simulate(ctx context.Context, in *iam.SimulatePrincipalPolicyInput) (map[string]string, error) {
	out, err := o.iam.SimulatePrincipalPolicy(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("SimulatePrincipalPolicy failed: %w", err)
	}
	decisions := make(map[string]string, len(out.EvaluationResults))
	for _, r := range out.EvaluationResults {
		if r.EvalActionName != nil {
			decisions[*r.EvalActionName] = string(r.EvalDecision)
		}
	}
	return decisions, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "no decision returned"
	}
	return s
}
