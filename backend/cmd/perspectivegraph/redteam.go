package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	awsconn "github.com/luiacuaniello/perspectivegraph/internal/connector/aws"
	"github.com/luiacuaniello/perspectivegraph/internal/redteam"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// runRedteam settles the engine's privilege-escalation claims against AWS's own policy
// evaluator, so the scores can be graded by something other than the engine that
// produced them:
//
//	perspectivegraph redteam -principal arn:aws:iam::123:role/app     # one principal
//	perspectivegraph redteam -principal arn:…:role/a,arn:…:role/b     # several
//	perspectivegraph redteam -roles                                   # every role in the account
//	perspectivegraph redteam -roles -role arn:aws:iam::123:role/pg-ro # via a read-only role
//	perspectivegraph redteam -compare -roles                          # engine vs AWS, and fail on disagreement
//
// It is READ-ONLY and creates nothing. Every check is one `iam:SimulatePrincipalPolicy`
// call - AWS's own evaluator, run as a dry run - so this costs nothing and needs no
// vulnerable infrastructure to point at. `-roles` additionally calls `iam:ListRoles`,
// also read-only and free.
//
// What makes the answer worth having is that the simulation applies what the engine's
// own policy evaluator deliberately skips: service control policies and condition keys
// (and, until the connector carried it through, permission boundaries). A principal the
// engine reports as able to escalate but that reality stops comes back DENIED here - a
// genuine false positive, found without exploiting anything.
//
// `-compare` closes the loop: it runs the ENGINE over the same account and puts the two
// verdicts side by side, exiting non-zero on any disagreement. That turns "the oracle
// says X" into a check something can fail, which is what `make boundary-lab-aws` needs
// in order to prove a false positive is actually gone rather than asserting it is.
func runRedteam(args []string) error {
	fs := flag.NewFlagSet("redteam", flag.ContinueOnError)
	region := fs.String("region", os.Getenv("AWS_REGION"), "AWS region (defaults to $AWS_REGION; IAM is global but the SDK needs one)")
	assumeRole := fs.String("role", "", "optional cross-account read-only role ARN to assume first")
	principal := fs.String("principal", "", "ARN of an IAM user/role/group to settle (comma-separated for several)")
	allRoles := fs.Bool("roles", false, "enumerate every role in the account and settle each")
	compare := fs.Bool("compare", false, "also run the engine over the account and report where it disagrees with AWS (non-zero exit on disagreement)")
	limit := fs.Int("limit", 200, "with -roles, stop after this many roles")
	resource := fs.String("resource", "", "settle the claim over this resource ARN instead of account-wide, which is what reveals a grant scoped to specific resources")
	record := fs.String("record", "", "with -compare, append each principal's two verdicts to this file as a lab check (one JSON object per line, for scripts/lab-record.py)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *principal == "" && !*allRoles {
		return fmt.Errorf("need -principal <arn> or -roles")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	opts := []func(*awsconfig.LoadOptions) error{}
	if *region != "" {
		opts = append(opts, awsconfig.WithRegion(*region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}
	if *assumeRole != "" {
		cfg.Credentials = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), *assumeRole)
	}
	client := iam.NewFromConfig(cfg)
	oracle := redteam.NewAWSOracle(client)

	principals := splitARNs(*principal)
	if *allRoles {
		principals, err = listRoleARNs(ctx, client, *limit)
		if err != nil {
			return err
		}
		fmt.Printf("settling escalation claims for %d role(s) in the account\n\n", len(principals))
	}

	if *compare {
		return compareEngineToAWS(ctx, oracle, *region, *assumeRole, principals, *record)
	}

	var held, blocked, unsettled int
	for _, arn := range principals {
		res, err := oracle.Check(ctx, redteam.EscalationClaimOn(arn, *resource))
		if err != nil {
			return fmt.Errorf("check %s: %w", arn, err)
		}
		switch res.Decision {
		case redteam.Allowed:
			held++
			fmt.Printf("  ESCALATES  %s\n             %s\n", shortARN(arn), res.Evidence)
		case redteam.Denied:
			blocked++
			fmt.Printf("  no privesc  %s\n", shortARN(arn))
		default:
			unsettled++
			fmt.Printf("  unsettled   %s (%s)\n", shortARN(arn), res.Evidence)
		}
	}

	fmt.Printf("\n%d principal(s): %d hold an escalation primitive, %d do not, %d unsettled\n",
		len(principals), held, blocked, unsettled)
	fmt.Println("AWS's own evaluator answered, applying the SCPs and condition keys the engine's")
	fmt.Println("policy reader skips. Nothing was created or changed.")
	return nil
}

// compareEngineToAWS grades the ENGINE against AWS on the same principals: it runs the
// live connector over the account, reads which principals the engine claims can reach
// account-admin, and puts that next to what SimulatePrincipalPolicy says.
//
// This is the part that makes a fix checkable. An oracle alone can only report what AWS
// believes; only running both can show that the engine now believes the same thing. A
// disagreement is a real finding either way - the engine over-reporting (a false
// positive) or under-reporting (a miss) - so it exits non-zero rather than printing a
// number nobody has to act on.
//
// The collect is read-only, like everything else here.
func compareEngineToAWS(ctx context.Context, oracle *redteam.AWSOracle, region, assumeRole string, principals []string, recordPath string) error {
	conn, err := awsconn.NewFromConfig(ctx, awsconn.Config{Mode: "sdk", Region: region, RoleARN: assumeRole})
	if err != nil {
		return fmt.Errorf("build sdk connector: %w", err)
	}
	events, err := conn.Collect(ctx)
	if err != nil {
		// Collect joins per-feed errors and still returns what did arrive; the IAM feed
		// is the one this needs, so a network-feed failure must not stop the comparison.
		fmt.Fprintf(os.Stderr, "redteam: partial collect: %v\n", err)
	}
	claims := engineEscalations(events)

	fmt.Printf("\n  %-42s %-12s %-12s\n", "principal", "engine", "AWS")
	fmt.Printf("  %s\n", strings.Repeat("-", 74))

	var agree, disagree, unsettled int
	for _, arn := range principals {
		res, err := oracle.Check(ctx, redteam.EscalationClaim(arn))
		if err != nil {
			return fmt.Errorf("check %s: %w", arn, err)
		}
		awsSays := "unsettled"
		switch res.Decision {
		case redteam.Allowed:
			awsSays = "ESCALATES"
		case redteam.Denied:
			awsSays = "no privesc"
		}
		engineSays, mark, outcome := grade(claims[arn], res.Decision)
		verdict := "unsettled"
		switch outcome {
		case outcomeAgree:
			agree++
			verdict = "agree"
		case outcomeDisagree:
			disagree++
			verdict = "disagree"
		default:
			unsettled++
		}
		fmt.Printf("  %-42s %-12s %-12s %s\n", shortARN(arn), engineSays, awsSays, mark)
		if recordPath != "" {
			if err := appendCheck(recordPath, map[string]string{"case": shortARN(arn),
				"question": "Can this identity make itself administrator?", "referee": "IAM SimulatePrincipalPolicy",
				"aws": awsSays, "engine": engineSays, "verdict": verdict}); err != nil {
				return err
			}
		}
	}

	fmt.Printf("\n%d principal(s): %d agree, %d disagree, %d unsettled\n",
		len(principals), agree, disagree, unsettled)
	if disagree > 0 {
		return fmt.Errorf("the engine disagrees with AWS on %d principal(s) - each is a false positive or a miss", disagree)
	}
	fmt.Println("The engine and AWS's own policy evaluator returned the same verdict for every")
	fmt.Println("settled principal. Nothing was created or changed.")
	return nil
}

// engineEscalations reads the engine's escalation claims out of the collected events:
// which principals it says can reach account-admin, and which it saw at all.
//
// The two are separate on purpose. A principal absent from the graph produced no claim,
// and scoring that as "the engine says no" would turn a coverage gap into fake agreement.
// engineEscalations reads the engine's escalation claims out of collected events, keyed
// by principal ARN.
//
// `scoped` marks the claims the engine itself qualified as resource-scoped: the
// permission is held only over specific resources, never account-wide. That matters for
// the comparison, because the oracle's unscoped question is account-wide - AWS evaluates
// an unnamed resource as `*` - so a scoped grant answers implicitDeny there. Grading
// that as a disagreement would fail the engine for a question nobody asked it.
//
// `conditional` marks the claims the engine reported unverified because a Deny it cannot
// evaluate might block them (deny_condition_unevaluated). The oracle answers for one
// request context - with an IfExists condition and no MFA key supplied, the Deny applies -
// so its "no" settles only that context, not the claim.
func engineEscalations(events []ontology.Event) map[string]claim {
	claims := map[string]claim{}
	arnByID := map[string]string{}
	for _, ev := range events {
		for _, n := range ev.Nodes {
			if arn, ok := n.Properties[ontology.PropARN].(string); ok && arn != "" {
				arnByID[n.ID] = arn
				c := claims[arn]
				c.collected = true
				claims[arn] = c
			}
		}
	}
	for _, ev := range events {
		for _, e := range ev.Edges {
			if e.Type != ontology.EdgeCanEscalateTo {
				continue
			}
			arn := arnByID[e.From]
			if arn == "" {
				continue
			}
			c := claims[arn]
			c.escalates = true
			// The engine draws one escalation edge per principal, and its qualifiers are the
			// claim's: resource-scoped, or blocked under a condition it cannot evaluate.
			c.scoped, _ = e.Properties["resource_scoped"].(bool)
			c.conditional, _ = e.Properties["deny_condition_unevaluated"].(bool)
			claims[arn] = c
		}
	}
	return claims
}

// claim is what the engine said about one principal.
type claim struct{ collected, escalates, scoped, conditional bool }

const (
	outcomeAgree = iota
	outcomeDisagree
	outcomeUnsettled
)

// grade puts the engine's claim about one principal next to AWS's answer.
func grade(c claim, d redteam.Decision) (engineSays, mark string, outcome int) {
	engineSays = verdict(c.escalates)
	switch {
	case !c.collected:
		// The engine never saw this principal, so it made no claim to grade. Saying
		// "agree" here would credit the engine for a question it was not asked.
		return "not collected", "unsettled", outcomeUnsettled
	case d == redteam.Inconclusive:
		return engineSays, "unsettled", outcomeUnsettled
	case c.scoped && d == redteam.Denied:
		// The engine qualified this claim as resource-scoped and the oracle asked
		// the account-wide question, so the two are not answering the same thing.
		// Calling it a disagreement would fail the engine for a question nobody
		// asked it; settling it means re-running with -resource <arn>.
		return "scoped", "unsettled (scoped)", outcomeUnsettled
	case c.conditional && d == redteam.Denied:
		// The engine said the escalation holds only when a condition does not, and the
		// oracle evaluated the one request context it was given. Its "no" is the case
		// the engine already named, not a refutation.
		return "conditional", "unsettled (conditional)", outcomeUnsettled
	case c.escalates == (d == redteam.Allowed):
		return engineSays, "agree", outcomeAgree
	default:
		return engineSays, "DISAGREE", outcomeDisagree
	}
}

func verdict(escalates bool) string {
	if escalates {
		return "ESCALATES"
	}
	return "no privesc"
}

// splitARNs accepts one ARN or a comma-separated list, so a caller can settle a
// handful of principals in a single account collect.
func splitARNs(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// listRoleARNs pages through the account's roles. Read-only and free.
func listRoleARNs(ctx context.Context, client *iam.Client, limit int) ([]string, error) {
	var arns []string
	p := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for p.HasMorePages() && len(arns) < limit {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam:ListRoles: %w", err)
		}
		for _, r := range page.Roles {
			if r.Arn == nil {
				continue
			}
			// AWS service-linked roles are managed by AWS and not an operator's
			// attack surface to fix, so they only add noise to the report.
			if strings.Contains(*r.Arn, ":role/aws-service-role/") {
				continue
			}
			arns = append(arns, *r.Arn)
			if len(arns) >= limit {
				break
			}
		}
	}
	return arns, nil
}

// shortARN trims the account prefix so the output stays readable.
func shortARN(arn string) string {
	if i := strings.Index(arn, ":role/"); i >= 0 {
		return "role/" + arn[i+len(":role/"):]
	}
	if i := strings.Index(arn, ":user/"); i >= 0 {
		return "user/" + arn[i+len(":user/"):]
	}
	return arn
}

// appendCheck adds one check to a lab's rows file, the form scripts/lab-record.py reads.
func appendCheck(path string, check map[string]string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- a path the operator names with -record
	if err != nil {
		return fmt.Errorf("record: %w", err)
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(check)
}
