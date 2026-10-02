package iam

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// TestExplicitDenyBeatsAllow pins AWS evaluation order: an account-wide explicit
// Deny wins over any Allow, so a denied action cannot enable a privesc primitive.
// Without this the engine reports a path AWS itself would refuse - a false positive.
func TestExplicitDenyBeatsAllow(t *testing.T) {
	a := actionSet{}.add("iam:*").deny("iam:AttachUserPolicy")

	if a.Allows("iam:AttachUserPolicy") {
		t.Error("explicit Deny must beat the iam:* Allow")
	}
	if !a.Allows("iam:PutUserPolicy") {
		t.Error("the Deny is action-specific; other iam actions must stay allowed")
	}
	for _, m := range detectPrivesc(a, asUser) {
		if strings.HasPrefix(m.Name, "iam:AttachUserPolicy") {
			t.Errorf("denied action must not yield a primitive: %s", m.Name)
		}
	}
}

// TestBlanketDenyRevokesAdmin: only a total Deny revokes admin. A narrow guardrail
// leaves a principal that can still do essentially everything, which is what
// matters for risk.
func TestBlanketDenyRevokesAdmin(t *testing.T) {
	if !(actionSet{}.add("*")).IsAdmin() {
		t.Error("Allow *:* is admin")
	}
	if (actionSet{}.add("*").deny("*")).IsAdmin() {
		t.Error("a blanket Deny must revoke admin")
	}
	if !(actionSet{}.add("*").deny("s3:DeleteBucket")).IsAdmin() {
		t.Error("a narrow guardrail Deny must not revoke admin")
	}
}

// TestResourceScopedGrantIsFlagged: a primitive granted only on specific resources
// is still real (self-privesc is a genuine technique) but must be marked, so the
// caller can score it below an account-wide grant instead of asserting it.
func TestResourceScopedGrantIsFlagged(t *testing.T) {
	broad := detectPrivesc(actionSet{}.add("iam:AttachUserPolicy"), asUser)
	if len(broad) == 0 {
		t.Fatal("account-wide grant must yield a primitive")
	}
	if broad[0].ScopedOnly {
		t.Error("account-wide grant must not be flagged resource-scoped")
	}

	scoped := detectPrivesc(actionSet{}.addScoped("iam:AttachUserPolicy"), asUser)
	if len(scoped) == 0 {
		t.Fatal("a resource-scoped grant is still a real primitive, not a miss")
	}
	if !scoped[0].ScopedOnly {
		t.Error("resource-scoped grant must be flagged")
	}

	// A two-action primitive is account-wide only if BOTH actions are.
	mixed := detectPrivesc(actionSet{}.add("iam:PassRole").addScoped("lambda:CreateFunction"), asUser)
	if len(mixed) == 0 {
		t.Fatal("mixed grant must still match the PassRole+Lambda primitive")
	}
	if !mixed[0].ScopedOnly {
		t.Error("a primitive with any scoped-only action must be flagged scoped")
	}
}

func TestResourceIsBroad(t *testing.T) {
	cases := map[string]struct {
		res  stringOrSlice
		want bool
	}{
		"missing":       {nil, true},
		"star":          {stringOrSlice{"*"}, true},
		"arn wildcard":  {stringOrSlice{"arn:aws:iam::1:user/*"}, true},
		"literal arn":   {stringOrSlice{"arn:aws:iam::1:user/bob"}, false},
		"literal multi": {stringOrSlice{"arn:aws:iam::1:user/bob", "arn:aws:iam::1:user/eve"}, false},
		"mixed":         {stringOrSlice{"arn:aws:iam::1:user/bob", "*"}, true},
	}
	for name, c := range cases {
		if got := resourceIsBroad(c.res); got != c.want {
			t.Errorf("%s: resourceIsBroad = %v, want %v", name, got, c.want)
		}
	}
}

// TestPolicyEvaluationEndToEnd drives the collector itself: a guardrail Deny
// removes the escalation edge entirely, while a resource-scoped grant keeps it at
// a reduced probability. These are the two behaviours that separate policy-aware
// evaluation from flat action matching.
func TestPolicyEvaluationEndToEnd(t *testing.T) {
	user := func(name, stmts string) string {
		return `{"UserDetailList":[{"UserName":"` + name + `","Arn":"arn:aws:iam::1:user/` + name +
			`","UserPolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[` + stmts + `]}}]}]}`
	}
	escalation := func(t *testing.T, bundle string) (ontology.Edge, bool) {
		t.Helper()
		events, err := New().Parse(strings.NewReader(bundle), ingestion.Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, ev := range events {
			for _, e := range ev.Edges {
				if e.Type == ontology.EdgeCanEscalateTo {
					return e, true
				}
			}
		}
		return ontology.Edge{}, false
	}

	t.Run("guardrail deny removes the edge", func(t *testing.T) {
		e, ok := escalation(t, user("bob",
			`{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"},`+
				`{"Effect":"Deny","Action":"iam:AttachUserPolicy","Resource":"*"}`))
		if ok {
			t.Errorf("denied privesc must not produce an escalation edge, got p=%.2f", e.ExploitProbability)
		}
	})

	t.Run("account-wide grant scores full", func(t *testing.T) {
		e, ok := escalation(t, user("dave", `{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"}`))
		if !ok {
			t.Fatal("account-wide privesc must produce an escalation edge")
		}
		if e.ExploitProbability != privescProb {
			t.Errorf("probability = %.2f, want %.2f", e.ExploitProbability, privescProb)
		}
		if e.Properties["resource_scoped"] == true {
			t.Error("account-wide grant must not be marked resource_scoped")
		}
	})

	t.Run("resource-scoped grant scores lower", func(t *testing.T) {
		e, ok := escalation(t, user("carol",
			`{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"arn:aws:iam::1:user/carol"}`))
		if !ok {
			t.Fatal("a resource-scoped privesc is real and must still produce an edge")
		}
		if e.ExploitProbability != scopedPrivescProb {
			t.Errorf("probability = %.2f, want %.2f", e.ExploitProbability, scopedPrivescProb)
		}
		if e.Properties["resource_scoped"] != true {
			t.Error("resource-scoped grant must carry resource_scoped=true")
		}
	})

	t.Run("resource-scoped deny is ignored (over-report, never miss)", func(t *testing.T) {
		e, ok := escalation(t, user("erin",
			`{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"},`+
				`{"Effect":"Deny","Action":"iam:AttachUserPolicy","Resource":"arn:aws:iam::1:user/someone"}`))
		if !ok {
			t.Fatal("a Deny confined to one resource must not remove an account-wide privesc")
		}
		if e.ExploitProbability != privescProb {
			t.Errorf("probability = %.2f, want %.2f", e.ExploitProbability, privescProb)
		}
	})
}

// The policy reader said it erred toward reporting too much. Two shapes made it report
// too little: an Allow written with NotAction was not read at all, and a Deny under a
// condition was applied as if it always held. Each case below is one policy shape, with
// what the engine must say about a role holding it.
func TestPolicyShapesTheReaderUsedToMisread(t *testing.T) {
	role := func(stmts string) string {
		return `{"RoleDetailList":[{"RoleName":"r","Arn":"arn:aws:iam::1:role/r",
		  "RolePolicyList":[{"PolicyName":"p","PolicyDocument":{"Statement":[` + stmts + `]}}]}]}`
	}
	const attach = `{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}`
	const withoutMFA = `"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}`
	for _, c := range []struct {
		name        string
		stmts       string
		escalates   bool
		prob        float64
		conditional bool
	}{
		{"an Allow of everything but one action grants the rest",
			`{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"*"}`, true, privescProb, false},
		{"an Allow of everything but IAM grants no IAM technique",
			`{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}`, false, 0, false},
		{"a Deny only without MFA leaves the escalation, unverified",
			attach + `,{"Effect":"Deny","Action":"iam:*","Resource":"*",` + withoutMFA + `}`, true, conditionalDenyProb, true},
		{"an unconditional Deny still removes it",
			attach + `,{"Effect":"Deny","Action":"iam:*","Resource":"*"}`, false, 0, false},
		{"a conditional Deny on one technique leaves another at full weight",
			attach + `,{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"*"}` +
				`,{"Effect":"Deny","Action":"iam:AttachRolePolicy","Resource":"*",` + withoutMFA + `}`, true, privescProb, false},
		{"a Deny on all but some resources is not account-wide",
			attach + `,{"Effect":"Deny","Action":"iam:*","NotResource":"arn:aws:iam::1:role/sandbox-*"}`, true, privescProb, false},
		{"a Deny of everything but S3 is not applied",
			attach + `,{"Effect":"Deny","NotAction":"s3:*","Resource":"*"}`, true, privescProb, false},
		{"an administrator under a conditional Deny of everything is unverified",
			`{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*",` + withoutMFA + `}`,
			true, conditionalDenyProb, true},
	} {
		_, edges := parseRoles(t, role(c.stmts))
		e, ok := edges["r"]
		if ok != c.escalates {
			t.Errorf("%s: escalates = %v, want %v (%v)", c.name, ok, c.escalates, e.Properties["primitives"])
			continue
		}
		if !ok {
			continue
		}
		if e.ExploitProbability != c.prob {
			t.Errorf("%s: p = %.2f, want %.2f", c.name, e.ExploitProbability, c.prob)
		}
		if got, _ := e.Properties[propDenyConditional].(bool); got != c.conditional {
			t.Errorf("%s: %s = %v, want %v", c.name, propDenyConditional, got, c.conditional)
		}
	}
}
