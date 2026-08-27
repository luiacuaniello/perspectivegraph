package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// stubTransport serves one account's canned bundle, so a fan-out can be exercised
// without credentials - the same argument the fixtures transport exists for.
type stubTransport struct {
	account string
	network string
	err     error
}

func (stubTransport) Mode() string                     { return "stub" }
func (s stubTransport) Account(context.Context) string { return s.account }
func (s stubTransport) Fetch(_ context.Context, f Feed) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if f != FeedNetwork {
		return nil, nil
	}
	return []byte(s.network), nil
}

const oneInstance = `{
  "provider": "aws",
  "security_groups": [ { "GroupId": "sg-open", "IpPermissions": [ { "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] } ] } ],
  "instances": [ { "InstanceId": "i-shared", "SecurityGroups": [ { "GroupId": "sg-open" } ] } ]
}`

// The point of the fan-out: two accounts that each own an i-shared are two machines,
// each filed under the account it actually lives in. Before this they were one node
// with both accounts' edges - a machine that exists in neither.
func TestFanOutKeepsAccountsApart(t *testing.T) {
	m := &multiConnector{accounts: []*Connector{
		New(stubTransport{account: "111111111111", network: oneInstance}),
		New(stubTransport{account: "222222222222", network: oneInstance}),
	}}

	evs, err := m.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	seen := map[string]string{} // node id -> account
	for _, ev := range evs {
		for _, n := range ev.Nodes {
			if n.Label != ontology.LabelVirtualMachine {
				continue
			}
			acct, _ := n.Properties[ontology.PropAccount].(string)
			seen[n.ID] = acct
		}
	}
	if len(seen) != 2 {
		t.Fatalf("expected one machine per account, got %d: %v", len(seen), seen)
	}
	accounts := map[string]bool{}
	for _, a := range seen {
		accounts[a] = true
	}
	if !accounts["111111111111"] || !accounts["222222222222"] {
		t.Errorf("assets were not filed under both accounts: %v", seen)
	}
}

// An expired role in one account must cost that account's assets for a pass, not the
// estate's. This is the same rule a failing feed already follows one level down.
func TestOneBadAccountDoesNotSinkTheOthers(t *testing.T) {
	m := &multiConnector{accounts: []*Connector{
		New(stubTransport{account: "111111111111", err: context.DeadlineExceeded}),
		New(stubTransport{account: "222222222222", network: oneInstance}),
	}}

	evs, err := m.Collect(context.Background())
	if err == nil {
		t.Error("the failing account was not reported at all")
	}
	var machines int
	for _, ev := range evs {
		for _, n := range ev.Nodes {
			if n.Label == ontology.LabelVirtualMachine {
				machines++
			}
		}
	}
	if machines != 1 {
		t.Errorf("got %d machines from the healthy account, want 1", machines)
	}
}

// Mode is what an operator reads in GET /connectors. "sdk" alone would not tell them
// whether the second account they configured is actually being pulled.
func TestModeReportsTheAccountCount(t *testing.T) {
	m := &multiConnector{accounts: []*Connector{
		New(stubTransport{account: "1"}), New(stubTransport{account: "2"}),
	}}
	if got := m.Mode(); !strings.Contains(got, "2 accounts") {
		t.Errorf("Mode() = %q, want it to name how many accounts are behind it", got)
	}
}

// The role list is operator input, so its edges matter: a trailing comma must not turn
// into an extra account read with the ambient credentials.
func TestSplitARNs(t *testing.T) {
	got := splitARNs("arn:a, arn:b ,,")
	if len(got) != 2 || got[0] != "arn:a" || got[1] != "arn:b" {
		t.Errorf("splitARNs = %#v, want the two roles trimmed and the blanks dropped", got)
	}
	if len(splitARNs("")) != 0 {
		t.Error("an empty list must stay empty - it means the ambient account, not one blank role")
	}
}
