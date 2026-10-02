package ingestion

import "testing"

// A resource policy is public when it lets every principal in, with no condition that
// narrows who - and a condition only on the transport narrows nothing.
func TestResourcePolicyPublic(t *testing.T) {
	for _, c := range []struct {
		name   string
		policy string
		public bool
	}{
		{"anyone may read", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`, true},
		{"anyone, written as AWS *", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["s3:Get*"],"Resource":"*"}]}`, true},
		{"anyone, over TLS only", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, true},
		{"anyone from one VPC endpoint", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}]}`, false},
		{"anyone in the organization", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`, false},
		{"one role", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::2:role/r"},"Action":"s3:GetObject"}]}`, false},
		{"allowed, then denied to everyone", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"},{"Effect":"Deny","Principal":"*","Action":"s3:*"}]}`, false},
		{"a single statement, not a list", `{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:*"}}`, true},
		{"no policy", ``, false},
	} {
		p, err := ParseResourcePolicy(c.policy)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := p.Public("s3:GetObject"); got != c.public {
			t.Errorf("%s: public = %v, want %v", c.name, got, c.public)
		}
	}
}

func TestResourcePolicyGrantees(t *testing.T) {
	p, err := ParseResourcePolicy(map[string]any{"Statement": []any{
		map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": []any{
			"arn:aws:iam::222222222222:role/analytics", "222222222222", "arn:aws:iam::333333333333:user/ops"}},
			"Action": "s3:GetObject"},
		map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::444444444444:role/other"},
			"Action": "s3:ListBucket"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := p.Grantees("s3:GetObject")
	if len(got) != 2 || got[0] != "arn:aws:iam::222222222222:role/analytics" || got[1] != "arn:aws:iam::333333333333:user/ops" {
		t.Errorf("grantees of s3:GetObject = %v, want the role and the user, not the bare account or the ListBucket grant", got)
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		p, s string
		want bool
	}{
		{"s3:*", "s3:getobject", true}, {"s3:get*", "s3:getobject", true}, {"s3:put*", "s3:getobject", false},
		{"*", "lambda:invokefunction", true}, {"lambda:invoke*url", "lambda:invokefunctionurl", true},
		{"lambda:invokefunction", "lambda:invokefunctionurl", false},
	} {
		if got := globMatch(c.p, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.p, c.s, got)
		}
	}
}
