package remediation

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func TestGenerateNetworkPolicyForExposedContainer(t *testing.T) {
	p := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-alb"},
			{ID: "c", Label: ontology.LabelContainer, Name: "payments",
				Properties: map[string]any{"k8s_ns": "prod"}},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "payments-admin",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeExposes, From: "lb", To: "c"},
			{EdgeType: ontology.EdgeAssumes, From: "c", To: "role"},
		},
	}

	sugs := Generate(p)
	if len(sugs) != 2 {
		t.Fatalf("expected 2 suggestions (netpol + iam), got %d", len(sugs))
	}

	byKind := map[string]Suggestion{}
	for _, s := range sugs {
		byKind[s.Kind] = s
	}

	np, ok := byKind["k8s-networkpolicy"]
	if !ok {
		t.Fatal("expected a k8s-networkpolicy suggestion")
	}
	for _, want := range []string{"kind: NetworkPolicy", "namespace: prod", "app: payments", "ingress: []"} {
		if !strings.Contains(np.Content, want) {
			t.Errorf("network policy missing %q:\n%s", want, np.Content)
		}
	}

	tf, ok := byKind["terraform"]
	if !ok {
		t.Fatal("expected a terraform IAM suggestion")
	}
	if !strings.Contains(tf.Content, "least-privilege") {
		t.Errorf("terraform should scope down the role:\n%s", tf.Content)
	}
}

func TestGenerateCloudPath(t *testing.T) {
	p := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "public-alb"},
			{ID: "vm", Label: ontology.LabelVirtualMachine, Name: "web"},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "web-admin", Properties: map[string]any{ontology.PropCrownJewel: true}},
			{ID: "bucket", Label: ontology.LabelBucket, Name: "customer-exports", Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeRoutesTo, From: "lb", To: "vm"},
			{EdgeType: ontology.EdgeAssumes, From: "vm", To: "role"},
			{EdgeType: ontology.EdgeHasPermission, From: "role", To: "bucket"},
		},
	}
	sugs := Generate(p)
	// SG revoke + IAM scope-down + data-store policy = 3.
	if len(sugs) != 3 {
		t.Fatalf("expected 3 suggestions, got %d: %+v", len(sugs), sugs)
	}
}

func TestGeneratePrivescAndLateralPaths(t *testing.T) {
	// IAM privesc: a publicly-assumable role escalates to account-admin.
	privesc := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "r", Label: ontology.LabelIAMRole, Name: "public-deployer",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "admin", Label: ontology.LabelIAMRole, Name: "account-admin (effective)",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{{EdgeType: ontology.EdgeCanEscalateTo, From: "r", To: "admin"}},
	}
	sugs := Generate(privesc)
	if len(sugs) != 1 {
		t.Fatalf("privesc path: expected 1 suggestion, got %d", len(sugs))
	}
	s := sugs[0]
	for _, want := range []string{`Effect   = "Deny"`, "iam:PassRole", "iam:CreatePolicyVersion", "publicly assumable"} {
		if !strings.Contains(s.Content, want) {
			t.Errorf("privesc remediation missing %q:\n%s", want, s.Content)
		}
	}
	// Apply-ready: the deny policy must not carry a REPLACE placeholder.
	if strings.Contains(s.Content, "REPLACE_WITH") {
		t.Errorf("privesc deny policy should be apply-ready, found a placeholder:\n%s", s.Content)
	}

	// Cloud lateral movement: a CONNECTS_TO edge must produce a segmentation fix.
	lateral := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "web", Label: ontology.LabelVirtualMachine, Name: "web-tier",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "db", Label: ontology.LabelVirtualMachine, Name: "customer-db",
				Properties: map[string]any{ontology.PropCrownJewel: true}},
		},
		Steps: []analyzer.Step{{EdgeType: ontology.EdgeConnectsTo, From: "web", To: "db"}},
	}
	lat := Generate(lateral)
	if len(lat) != 1 || !strings.Contains(lat[0].Content, "lateral reachability") {
		t.Fatalf("lateral path: expected a segmentation suggestion, got %+v", lat)
	}
}

// The namespace comes from ingested data, and the generated manifest is proposed as a
// fix - so a value carrying a line break used to insert keys of its own into a
// NetworkPolicy. Every environment-derived string in a generated file is an RFC 1123
// label or it does not go in.
func TestGeneratedManifestCannotBeShapedByTheNamespaceProperty(t *testing.T) {
	hostile := map[string]string{
		"yaml break":      "prod\n  hostNetwork: true\n  x: ",
		"comment escape":  "prod # injected",
		"uppercase":       "PROD",
		"leading dash":    "-prod-",
		"path separator":  "kube-system/../prod",
		"over the length": strings.Repeat("a", 200),
	}
	for name, ns := range hostile {
		t.Run(name, func(t *testing.T) {
			p := analyzer.AttackPath{
				Nodes: []ontology.Node{
					{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-alb"},
					{ID: "c", Label: ontology.LabelContainer, Name: "payments",
						Properties: map[string]any{"k8s_ns": ns}},
					{ID: "j", Label: ontology.LabelDatabase, Name: "customers",
						Properties: map[string]any{ontology.PropCrownJewel: true}},
				},
				Steps: []analyzer.Step{
					{EdgeType: ontology.EdgeExposes, From: "lb", To: "c"},
					{EdgeType: ontology.EdgeConnectsTo, From: "c", To: "j"},
				},
			}
			var netpol string
			for _, s := range Generate(p) {
				if s.Kind == "k8s-networkpolicy" {
					netpol = s.Content
				}
			}
			if netpol == "" {
				t.Fatal("no NetworkPolicy generated")
			}
			var got string
			for _, line := range strings.Split(netpol, "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "namespace:"); ok {
					got = strings.TrimSpace(v)
				}
			}
			if got == "" {
				t.Fatal("no namespace line in the manifest")
			}
			if !isRFC1123Label(got) {
				t.Errorf("namespace %q is not an RFC 1123 label - the property shaped the manifest", got)
			}
		})
	}
}

func isRFC1123Label(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// A crown jewel open to anyone has no edge to cut: the fix is to close it. For a bucket
// that is an S3 public access block, apply-ready from the bucket's name alone. It
// carries no cut edge, so nothing claims to verify it by removing one.
func TestADirectAccessBucketGetsAPublicAccessBlock(t *testing.T) {
	bucket := ontology.Node{ID: "Bucket:exports", Label: ontology.LabelBucket, Name: "exports",
		Properties: map[string]any{ontology.PropPublicAccess: true, ontology.PropCrownJewel: true}}
	p := analyzer.AttackPath{ID: "ap-exports", Score: 1, Nodes: []ontology.Node{bucket}, DirectAccess: true}
	got := Generate(p)
	if len(got) != 1 {
		t.Fatalf("%d suggestions, want the public access block", len(got))
	}
	s := got[0]
	if s.Kind != "terraform" || !strings.Contains(s.Content, `aws_s3_bucket_public_access_block`) ||
		!strings.Contains(s.Content, `bucket                  = "exports"`) || !strings.Contains(s.Content, "restrict_public_buckets = true") {
		t.Errorf("unexpected artifact:\n%s", s.Content)
	}
	if s.Cut != (CutEdge{}) {
		t.Errorf("a fix with no edge to cut claims one: %+v", s.Cut)
	}
	if plan := Plan([]analyzer.AttackPath{p}); len(plan) != 1 || plan[0].CoveragePct != 1 {
		t.Errorf("the plan should cover the direct-access path with that fix: %+v", plan)
	}
}

// A role open to anyone gets a hint - its right trust policy names principals only its
// owner knows - and a role that is not open gets none.
func TestOnlyAnOpenRoleGetsTheTrustHint(t *testing.T) {
	open := ontology.Node{ID: "IAM_Role:open", Label: ontology.LabelIAMRole, Name: "open",
		Properties: map[string]any{ontology.PropPublicAccess: true}}
	closed := ontology.Node{ID: "IAM_Role:closed", Label: ontology.LabelIAMRole, Name: "closed"}
	hints := Hints(analyzer.AttackPath{Nodes: []ontology.Node{open, closed}})
	if len(hints) != 1 || !strings.Contains(hints[0], "**open** can be assumed by anyone") {
		t.Errorf("hints = %q, want one for the open role only", hints)
	}
}

// A role any GitHub repository can assume is fixed in its trust policy: the condition on
// the token's subject is what was missing, and the fix cuts the edge the route enters by.
func TestAnOpenGitHubTrustGetsItsSubjectPinned(t *testing.T) {
	p := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{ID: "gh", Label: ontology.LabelIdentityProvider, Name: "GitHub Actions (any repository)",
				Properties: map[string]any{ontology.PropInternetExposed: true, "oidc_issuer": "token.actions.githubusercontent.com"}},
			{ID: "role", Label: ontology.LabelIAMRole, Name: "github-deploy",
				Properties: map[string]any{ontology.PropAccount: "123456789012"}},
			{ID: "admin", Label: ontology.LabelIAMRole, Name: "account-admin"},
		},
		Steps: []analyzer.Step{
			{EdgeType: ontology.EdgeAuthenticates, From: "gh", To: "role"},
			{EdgeType: ontology.EdgeCanEscalateTo, From: "role", To: "admin"},
		},
	}
	var pin *Suggestion
	for _, s := range Generate(p) {
		if strings.HasPrefix(s.Filename, "pin-github-subject-") {
			s := s
			pin = &s
		}
	}
	if pin == nil {
		t.Fatalf("no subject-pinning fix among %+v", Generate(p))
	}
	for _, want := range []string{
		"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
		`variable = "token.actions.githubusercontent.com:sub"`, "sts:AssumeRoleWithWebIdentity",
	} {
		if !strings.Contains(pin.Content, want) {
			t.Errorf("fix lacks %q:\n%s", want, pin.Content)
		}
	}
	if pin.Cut != (CutEdge{From: "gh", To: "role", Type: string(ontology.EdgeAuthenticates)}) {
		t.Errorf("fix cuts %+v, want the edge the route enters by", pin.Cut)
	}

	// A pinned trust is not an entry point, and gets no such fix.
	p.Nodes[0].Properties[ontology.PropInternetExposed] = false
	for _, s := range Generate(p) {
		if strings.HasPrefix(s.Filename, "pin-github-subject-") {
			t.Error("a pinned trust was offered a pinning fix")
		}
	}
}

// A load balancer in front of an ECS service: the service's door is a security group, so
// the fix is the security-group rule, not a Kubernetes NetworkPolicy, which no ECS task
// obeys. A Kubernetes pod behind the same kind of edge still gets the NetworkPolicy.
func TestAnECSServiceIsNotFixedWithANetworkPolicy(t *testing.T) {
	path := func(target ontology.Node) analyzer.AttackPath {
		return analyzer.AttackPath{
			Nodes: []ontology.Node{
				{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "web", Properties: map[string]any{ontology.PropInternetExposed: true}},
				target,
			},
			Steps: []analyzer.Step{{EdgeType: ontology.EdgeRoutesTo, From: "lb", To: target.ID}},
		}
	}
	kinds := func(p analyzer.AttackPath) map[string]bool {
		out := map[string]bool{}
		for _, s := range Generate(p) {
			out[s.Kind] = true
		}
		return out
	}
	ecs := kinds(path(ontology.Node{ID: "svc", Label: ontology.LabelContainer, Name: "api",
		Properties: map[string]any{"ecs_cluster": "prod"}}))
	if ecs["k8s-networkpolicy"] || !ecs["terraform"] {
		t.Errorf("an ECS service behind a load balancer: got %v, want the security-group fix only", ecs)
	}
	pod := kinds(path(ontology.Node{ID: "pod", Label: ontology.LabelContainer, Name: "api",
		Properties: map[string]any{"k8s_ns": "prod"}}))
	if !pod["k8s-networkpolicy"] {
		t.Errorf("a Kubernetes pod behind a load balancer: got %v, want the NetworkPolicy", pod)
	}
}

func TestGenerateRemediationForLambdaFunctionURLExposure(t *testing.T) {
	p := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{
				ID:    "lambda",
				Label: ontology.LabelFunction,
				Name:  "public-handler",
				Properties: map[string]any{
					ontology.PropInternetExposed: true,
					ontology.PropExposure:        ontology.ExposureFunctionURL,
				},
			},
			{
				ID:    "role",
				Label: ontology.LabelIAMRole,
				Name:  "lambda-execution-role",
			},
		},
		Steps: []analyzer.Step{
			{
				EdgeType: ontology.EdgeAssumes,
				From:     "lambda",
				To:       "role",
			},
		},
	}

	var found *Suggestion
	for _, s := range Generate(p) {
		if strings.Contains(s.Filename, "lambda") {
			s := s
			found = &s
			break
		}
	}

	if found == nil {
		t.Fatalf("expected remediation for Lambda Function URL exposure, got %+v", Generate(p))
	}

	if found.Kind != "terraform" {
		t.Errorf("kind = %q, want terraform", found.Kind)
	}

	for _, want := range []string{
		`aws_lambda_function_url`,
		`authorization_type = "AWS_IAM"`,
		`lambda:InvokeFunctionUrl`,
		`lambda:InvokeFunction`,
		`principal = "*"`,
		`aws lambda remove-permission`,
	} {
		if !strings.Contains(found.Content, want) {
			t.Errorf("remediation missing %q:\n%s", want, found.Content)
		}
	}

	if found.Cut != (CutEdge{
		From: "lambda",
		To:   "role",
		Type: string(ontology.EdgeAssumes),
	}) {
		t.Errorf("cut = %+v, want Lambda -> role ASSUMES", found.Cut)
	}
}

func TestGenerateRemediationForLambdaPolicyExposure(t *testing.T) {
	p := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{
				ID:    "lambda",
				Label: ontology.LabelFunction,
				Name:  "public-handler",
				Properties: map[string]any{
					ontology.PropInternetExposed: true,
					ontology.PropExposure:        ontology.ExposureFunctionPolicy,
				},
			},
			{
				ID:    "role",
				Label: ontology.LabelIAMRole,
				Name:  "lambda-execution-role",
			},
		},
		Steps: []analyzer.Step{
			{
				EdgeType: ontology.EdgeAssumes,
				From:     "lambda",
				To:       "role",
			},
		},
	}

	var found *Suggestion
	for _, s := range Generate(p) {
		if strings.Contains(s.Filename, "lambda") {
			s := s
			found = &s
			break
		}
	}

	if found == nil {
		t.Fatalf("expected remediation for Lambda policy exposure, got %+v", Generate(p))
	}

	for _, want := range []string{
		`aws_lambda_permission`,
		`principal = "*"`,
		`source_arn`,
		`source_account`,
	} {
		if !strings.Contains(found.Content, want) {
			t.Errorf("remediation missing %q:\n%s", want, found.Content)
		}
	}
}

func TestNoRemediationForNonExposedLambda(t *testing.T) {
	p := analyzer.AttackPath{
		Nodes: []ontology.Node{
			{
				ID:    "lambda",
				Label: ontology.LabelFunction,
				Name:  "private-handler",
				Properties: map[string]any{
					ontology.PropInternetExposed: false,
				},
			},
			{
				ID:    "role",
				Label: ontology.LabelIAMRole,
				Name:  "lambda-execution-role",
			},
		},
		Steps: []analyzer.Step{
			{
				EdgeType: ontology.EdgeAssumes,
				From:     "lambda",
				To:       "role",
			},
		},
	}

	for _, s := range Generate(p) {
		if strings.Contains(s.Filename, "lambda") {
			t.Errorf("non-exposed Lambda received remediation: %+v", s)
		}
	}
}

// An open function whose exposure the fix does not know - a node from another feed, or one
// whose exposure was never read - gets both fixes and how to tell which way is open, not
// an empty file. The two ways the lambda collector writes keep their own fix.
func TestAnOpenFunctionOfUnknownExposureGetsBothFixes(t *testing.T) {
	for exposure, generic := range map[string]bool{
		ontology.ExposureFunctionURL:      false,
		ontology.ExposureFunctionPolicy:   false,
		"":                                true,
		"reached through a custom domain": true,
	} {
		p := analyzer.AttackPath{
			Nodes: []ontology.Node{
				{ID: "lambda", Label: ontology.LabelFunction, Name: "public-handler", Properties: map[string]any{
					ontology.PropInternetExposed: true, ontology.PropExposure: exposure}},
				{ID: "role", Label: ontology.LabelIAMRole, Name: "lambda-execution-role"},
			},
			Steps: []analyzer.Step{{EdgeType: ontology.EdgeAssumes, From: "lambda", To: "role"}},
		}
		var found *Suggestion
		for _, s := range Generate(p) {
			if strings.HasPrefix(s.Filename, "close-public-lambda-") {
				s := s
				found = &s
			}
		}
		if found == nil {
			t.Errorf("exposure %q: no fix for the open function", exposure)
			continue
		}
		hasURLFix := strings.Contains(found.Content, `authorization_type = "AWS_IAM"`)
		hasPolicyFix := strings.Contains(found.Content, "aws_lambda_permission")
		checks := strings.Contains(found.Content, `aws lambda get-function-url-config --function-name "public-handler"`) &&
			strings.Contains(found.Content, `aws lambda get-policy --function-name "public-handler"`)
		switch {
		case generic && !(hasURLFix && hasPolicyFix && checks):
			t.Errorf("exposure %q: want both fixes and the commands that tell them apart:\n%s", exposure, found.Content)
		case !generic && (checks || hasURLFix == hasPolicyFix):
			t.Errorf("exposure %q: want the one fix for that way:\n%s", exposure, found.Content)
		}
		if found.Cut != (CutEdge{From: "lambda", To: "role", Type: string(ontology.EdgeAssumes)}) {
			t.Errorf("exposure %q: cut = %+v, want the function's ASSUMES edge", exposure, found.Cut)
		}
	}
}
