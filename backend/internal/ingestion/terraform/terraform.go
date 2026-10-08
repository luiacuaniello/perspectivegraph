// Package terraform reads a Terraform plan as a change to an AWS estate: what the estate
// looks like before the plan is applied, what it looks like after, and what cannot be
// known until it is - so the merge gate can answer, before anything is deployed, whether
// a pull request opens a route from the internet to something that matters.
//
// The input is the plan as `terraform show -json <planfile>` writes it. The plan carries
// the state it starts from (prior_state), the state it would leave (planned_values) and
// the configuration it came from, whose references say what an identifier not assigned
// yet will be: an instance's security group, when both are created by the same plan, is
// whatever that group turns out to be.
//
// Nothing here evaluates AWS semantics. Each state is turned into the very shapes the
// AWS API returns - describe-instances, get-account-authorization-details, a Lambda
// function's URL and policy, a Custodian export of S3 - and handed to the collectors that
// already read those shapes from a live account (cloudnet, iam, lambda, custodian). A
// planned instance is judged exposed by the same code that judges a running one, and is
// keyed the same way, so it meets the estate where it already exists.
//
// A resource the plan creates has no identifier yet; it gets a placeholder that keeps the
// prefix AWS would give it (sg-, i-, igw-) and names the block of the configuration it
// stands for. An ARN AWS builds from a name - an IAM role's, a bucket's - is built the
// same way.
//
// A security group, a subnet and a route table serve whatever uses them, and a plan holds
// only what its configuration manages. Given the account's network as a live read fetched it
// (ingestion.Options.LiveNetwork), each state of the plan is laid over it and judged whole;
// without it, what the plan opens of those it did not create is listed as outside the plan
// (live.go).
//
// What it reads: VPC networking (security groups and their rules, subnets, route tables
// and routes, internet gateways, Elastic IPs), EC2 instances and their instance profiles,
// IAM roles, users, their policies and attachments and permissions boundaries, S3 buckets
// with their policies, ACLs and Block Public Access, and Lambda functions with their URLs
// and permissions. Load balancers, API Gateway, ECS and EKS are not read yet.
package terraform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/custodian"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/lambda"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Source is the collector's name: the gate's -source and the /gate/impact source.
const Source = "terraform"

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return Source }

// Parse returns the state the plan leaves, stamped with the commit.
func (c *Collector) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	ch, err := c.ParseChange(r, opts)
	return ch.After, err
}

// ParseChange reads a plan into the state it starts from, the state it leads to, and
// what it leaves unknown until apply.
func (c *Collector) ParseChange(r io.Reader, opts ingestion.Options) (ingestion.Change, error) {
	p, err := Read(r, opts.Account, "")
	if err != nil {
		return ingestion.Change{}, err
	}
	live, err := readLive(opts.LiveNetwork)
	if err != nil {
		return ingestion.Change{}, err
	}
	prior, planned := p.bundles(Prior), p.bundles(Planned)
	beyond := outside(prior.net, planned.net, live)
	// What the estate decides better than the plan. An instance whose exposure the plan
	// does not touch - same subnet and routes, same groups and rules, same addresses - is
	// exposed or not as the estate says: the plan may not describe its subnet's routing,
	// and then its own verdict rests on the security groups alone. Without an estate,
	// that verdict is the best there is, erring toward reporting, and it stays.
	settled := map[string]bool{}
	if opts.EstateKnown {
		for _, id := range unchangedExposure(prior.net, planned.net) {
			settled[ontology.ScopedID(ontology.LabelVirtualMachine, p.Account, id)] = true
		}
	}
	// With the account's network read, each state of the plan is judged laid over it (see
	// live.go): the instances the plan does not describe are judged with it.
	if live != nil {
		prior.view, planned.view = overlay(*live, prior.net), overlay(*live, planned.net)
	}
	was, err := p.feeds(prior)
	if err != nil {
		return ingestion.Change{}, err
	}
	now, err := p.feeds(planned)
	if err != nil {
		return ingestion.Change{}, err
	}
	// Compared before finish leaves anything to the estate, which it does on both sides.
	changed := changedNodes(was, now)
	before := p.finish(was, prior, ingestion.Options{}, settled, nil)
	after := p.finish(now, planned, opts, settled, changed)
	return ingestion.Change{Before: before, After: after, Unknown: planned.notes, Outside: beyond}, nil
}

// bundles is one state of the plan in the shapes of the AWS feeds.
type bundles struct {
	net netBundle
	// view is the network the state is judged on: the plan's own, or the plan's laid over
	// the account's when a live read gave it.
	view  netBundle
	iam   iamBundle
	fn    lambdaBundle
	s3    custodianBundle
	notes []string
	// partial are the assets the configuration does not manage but changes - a bucket
	// it only writes a policy for, a function it only adds a permission to. Their record
	// holds only what the plan says, so it can say they are open, never that they are
	// closed.
	partial map[string]bool
}

func (p *Plan) bundles(v View) bundles {
	var b bundles
	var n []string
	b.net, n = p.network(v)
	b.view = b.net
	b.notes = append(b.notes, n...)
	b.iam, n = p.iam(v)
	b.notes = append(b.notes, n...)
	b.fn, n = p.lambda(v)
	b.notes = append(b.notes, n...)
	b.s3, n = p.s3(v)
	b.notes = append(b.notes, n...)
	b.notes = dedupe(b.notes)

	b.partial = map[string]bool{}
	managed := map[string]bool{}
	for _, r := range p.Resources(v, "aws_lambda_function", "aws_s3_bucket") {
		if r.Managed() {
			managed[r.Type+"/"+p.nameOf(v, r)] = true
		}
	}
	for _, f := range b.fn.Functions {
		if !managed["aws_lambda_function/"+f.FunctionName] {
			b.partial[ontology.NewID(ontology.LabelFunction, f.FunctionArn)] = true
		}
	}
	for _, part := range b.s3.Policies {
		if part.Resource != "aws.s3" {
			continue
		}
		for _, bk := range part.Resources {
			name, _ := bk["Name"].(string)
			if !managed["aws_s3_bucket/"+name] {
				b.partial[ontology.NewID(ontology.LabelBucket, name)] = true
			}
		}
	}
	return b
}

// exposureProps are what the collectors write about whether the internet reaches an asset.
var exposureProps = []string{
	ontology.PropNetworkExposed, ontology.PropInternetExposed, ontology.PropPublicAccess,
	"exposed_ports", "exposed_management_ports", "net_reachability", "exposure", "public_via", "public_blocked_by",
}

// feeds turns one state of the plan into the events of the collectors that read each part.
func (p *Plan) feeds(b bundles) ([]ontology.Event, error) {
	inner := ingestion.Options{Account: p.Account}
	out := []ontology.Event{}
	for _, feed := range []struct {
		col    ingestion.Collector
		bundle any
		empty  bool
	}{
		{cloudnet.New(), b.view, len(b.view.SecurityGroups) == 0 && len(b.view.Instances) == 0},
		{iam.New(), b.iam, len(b.iam.RoleDetailList) == 0 && len(b.iam.UserDetailList) == 0},
		{lambda.New(), b.fn, len(b.fn.Functions) == 0},
		{custodian.New(), b.s3, len(b.s3.Policies) == 1 && len(b.s3.Policies[0].Resources) == 0},
	} {
		if feed.empty {
			continue
		}
		raw, err := json.Marshal(feed.bundle)
		if err != nil {
			return nil, err
		}
		evs, err := feed.col.Parse(bytes.NewReader(raw), inner)
		if err != nil {
			return nil, fmt.Errorf("terraform plan, %s part: %w", feed.col.Source(), err)
		}
		out = append(out, evs...)
	}
	return out, nil
}

// finish leaves to the estate what it decides better (settled, partial) and stamps with the
// commit the assets the configuration defines or changes, and those whose reachability the
// change changes.
func (p *Plan) finish(out []ontology.Event, b bundles, opts ingestion.Options, settled, changed map[string]bool) []ontology.Event {
	stamp := map[string]bool{}
	for id := range changed {
		stamp[id] = true
	}
	for _, inst := range b.net.Instances {
		stamp[ontology.ScopedID(ontology.LabelVirtualMachine, p.Account, inst.InstanceID)] = true
	}
	for _, r := range b.iam.RoleDetailList {
		stamp[ontology.NewID(ontology.LabelIAMRole, r.Arn)] = true
	}
	for _, u := range b.iam.UserDetailList {
		stamp[ontology.NewID(ontology.LabelUser, u.Arn)] = true
	}
	for _, f := range b.fn.Functions {
		stamp[ontology.NewID(ontology.LabelFunction, f.FunctionArn)] = true
	}
	for _, part := range b.s3.Policies {
		if part.Resource != "aws.s3" {
			continue
		}
		for _, bk := range part.Resources {
			name, _ := bk["Name"].(string)
			stamp[ontology.NewID(ontology.LabelBucket, name)] = true
		}
	}

	pr := opts.PRProps()
	for i := range out {
		for j := range out[i].Nodes {
			nd := &out[i].Nodes[j]
			open, _ := nd.Properties[ontology.PropNetworkExposed].(bool)
			if settled[nd.ID] || (b.partial[nd.ID] && !open) {
				for _, k := range exposureProps {
					delete(nd.Properties, k)
				}
			}
			if pr == nil || !stamp[nd.ID] {
				continue
			}
			if nd.Properties == nil {
				nd.Properties = map[string]any{}
			}
			for k, x := range pr {
				nd.Properties[k] = x
			}
		}
	}
	return out
}

func dedupe(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
