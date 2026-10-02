package ingestion

import "testing"

// A resource policy is public when it lets every principal in, unless a condition confines
// it to fixed values of the keys AWS lists - S3 Block Public Access's definition. The first
// cases are the ones GetBucketPolicyStatus judged on a real account in
// scripts/entrypoints-lab-aws.sh; three of them the reader used to call private.
func TestResourcePolicyPublic(t *testing.T) {
	when := func(cond string) string {
		return `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Condition":` + cond + `}]}`
	}
	for _, c := range []struct {
		name   string
		policy string
		public bool
	}{
		{"AWS: a Referer is no restriction", when(`{"StringLike":{"aws:Referer":"https://example.com/*"}}`), true},
		{"AWS: any VPC at all", when(`{"StringLike":{"aws:SourceVpc":"vpc-*"}}`), true},
		{"AWS: half the IPv4 internet", when(`{"IpAddress":{"aws:SourceIp":"0.0.0.0/1"}}`), true},
		{"AWS: one documentation range", when(`{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}`), false},
		{"AWS: one account", when(`{"StringEquals":{"aws:PrincipalAccount":"123456789012"}}`), false},
		{"a /8 is still narrow", when(`{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","203.0.113.7"]}}`), false},
		{"one wide range among narrow ones", when(`{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","0.0.0.0/0"]}}`), true},
		{"an IPv6 /32", when(`{"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}`), false},
		{"an IPv6 /31", when(`{"IpAddress":{"aws:SourceIp":"2001:db8::/31"}}`), true},
		{"every VPC endpoint but one", when(`{"StringNotEquals":{"aws:SourceVpce":"vpce-1"}}`), true},
		{"a VPC endpoint, if there is one", when(`{"StringEqualsIfExists":{"aws:SourceVpce":"vpce-1"}}`), true},
		{"a policy variable is no fixed value", when(`{"StringEquals":{"aws:SourceAccount":"${aws:PrincipalAccount}"}}`), true},
		{"every session of one role", when(`{"StringLike":{"aws:userid":"AROAEXAMPLEID:*"}}`), false},
		{"any access point of one account", when(`{"StringLike":{"s3:DataAccessPointArn":"arn:aws:s3:eu-west-1:123456789012:accesspoint/*"}}`), false},
		{"a Referer next to a fixed account", when(`{"StringLike":{"aws:Referer":"*"},"StringEquals":{"aws:SourceAccount":"123456789012"}}`), false},
		{"denied only without TLS, which an attacker has", `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"},
		  {"Effect":"Deny","Principal":"*","Action":"s3:*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, true},
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

// A Lambda function policy speaks to two doors: a direct call, and a call through the
// function URL. A statement confined to URL calls opens only the second; one requiring the
// IAM auth type does not open a URL without authentication.
func TestResourcePolicyThroughAFunctionURL(t *testing.T) {
	p, err := ParseResourcePolicy(`{"Statement":[
	  {"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl","Condition":{"StringEquals":{"lambda:FunctionUrlAuthType":"NONE"}}},
	  {"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction","Condition":{"Bool":{"lambda:InvokedViaFunctionUrl":"true"}}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Public("lambda:InvokeFunction") || p.Public("lambda:InvokeFunctionUrl") {
		t.Error("statements confined to URL calls open no direct call")
	}
	if !p.PublicThroughURL("NONE", "lambda:InvokeFunctionUrl") || !p.PublicThroughURL("NONE", "lambda:InvokeFunction") {
		t.Error("through a URL without authentication, both grants hold for anyone")
	}
	if p.PublicThroughURL("AWS_IAM", "lambda:InvokeFunctionUrl") {
		t.Error("a grant for NONE URLs does not hold for an AWS_IAM one")
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
