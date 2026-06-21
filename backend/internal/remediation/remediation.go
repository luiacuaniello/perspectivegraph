// Package remediation turns an attack path into concrete "cut an edge"
// artifacts. The insight from the analyzer is that breaking *any* single edge
// of a path neutralizes it — so instead of demanding every finding be fixed,
// AegisGraph proposes the cheapest cut: isolate the exposed workload with a
// Kubernetes NetworkPolicy, scope down an over-broad IAM role, or tighten a
// data store's access, generated as ready-to-review code.
package remediation

import (
	"fmt"
	"strings"

	"github.com/aegisgraph/aegisgraph/internal/analyzer"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

// Suggestion is one generated remediation artifact.
type Suggestion struct {
	Title     string `json:"title"`
	Kind      string `json:"kind"`      // "k8s-networkpolicy" | "terraform"
	Filename  string `json:"filename"`  // suggested file name
	Content   string `json:"content"`   // the artifact body (YAML/HCL)
	Rationale string `json:"rationale"` // which edge it cuts and why
}

// Generate inspects a path and emits remediation artifacts for the edges that
// are cheapest to cut, de-duplicated by kind+target.
func Generate(p analyzer.AttackPath) []Suggestion {
	index := map[string]ontology.Node{}
	for _, n := range p.Nodes {
		index[n.ID] = n
	}

	var out []Suggestion
	seen := map[string]bool{}
	add := func(s Suggestion) {
		key := s.Kind + "|" + s.Filename
		if !seen[key] {
			seen[key] = true
			out = append(out, s)
		}
	}

	for _, st := range p.Steps {
		from, to := index[st.From], index[st.To]
		switch st.EdgeType {
		case ontology.EdgeExposes, ontology.EdgeRoutesTo, ontology.EdgeHosts:
			if to.Label == ontology.LabelContainer {
				add(networkPolicy(to))
			} else if to.Label == ontology.LabelVirtualMachine && from.Label == ontology.LabelLoadBalancer {
				add(sgRevoke(from, to))
			}
		case ontology.EdgeAssumes:
			if to.Label == ontology.LabelIAMRole && to.Bool(ontology.PropCrownJewel) {
				add(iamScopeDown(to))
			}
		case ontology.EdgeHasPermission:
			if to.Label == ontology.LabelBucket || to.Label == ontology.LabelDatabase {
				add(dataStorePolicy(from, to))
			}
		}
	}
	return out
}

func networkPolicy(c ontology.Node) Suggestion {
	app := sanitize(c.Name)
	ns := propStr(c, "k8s_ns")
	if ns == "" {
		ns = "default"
	}
	content := fmt.Sprintf(`# AegisGraph auto-remediation — isolate %q to cut the ingress edge.
# Review and scope the ingress rules to only the senders this workload needs.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: aegis-deny-ingress-%s
  namespace: %s
spec:
  podSelector:
    matchLabels:
      app: %s
  policyTypes:
    - Ingress
  ingress: []   # default-deny: no ingress until explicitly allowed
`, c.Name, app, ns, app)

	return Suggestion{
		Title:     "Deny ingress to " + c.Name,
		Kind:      "k8s-networkpolicy",
		Filename:  "networkpolicy-" + app + ".yaml",
		Content:   content,
		Rationale: "Severs the network exposure edge into the container, breaking the path at the entry point.",
	}
}

func sgRevoke(lb, vm ontology.Node) Suggestion {
	name := sanitize(vm.Name)
	content := fmt.Sprintf(`# AegisGraph auto-remediation — remove the public ingress fronting %q (via %q).
# Replace the 0.0.0.0/0 rule on the relevant security group with your trusted CIDRs.
resource "aws_security_group_rule" "aegis_restrict_%s" {
  type              = "ingress"
  description       = "Restricted by AegisGraph (was 0.0.0.0/0)"
  security_group_id = "REPLACE_WITH_SG_ID"
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["10.0.0.0/8"] # TODO: your trusted ranges
}
`, vm.Name, lb.Name, name)

	return Suggestion{
		Title:     "Restrict public ingress to " + vm.Name,
		Kind:      "terraform",
		Filename:  "sg-restrict-" + name + ".tf",
		Content:   content,
		Rationale: "Removes the internet exposure on the load balancer / security group fronting the instance.",
	}
}

func iamScopeDown(role ontology.Node) Suggestion {
	name := sanitize(role.Name)
	content := fmt.Sprintf(`# AegisGraph auto-remediation — scope down over-privileged role %q.
# Detach the broad managed policy and attach a least-privilege one:
#   aws iam detach-role-policy --role-name %s --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
resource "aws_iam_role_policy" "aegis_least_privilege_%s" {
  name = "%s-least-privilege"
  role = %q
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [] # TODO: only the actions this workload actually needs
      Resource = []
    }]
  })
}
`, role.Name, role.Name, name, name, role.Name)

	return Suggestion{
		Title:     "Scope down IAM role " + role.Name,
		Kind:      "terraform",
		Filename:  "iam-scopedown-" + name + ".tf",
		Content:   content,
		Rationale: "Cuts the ASSUMES edge's value by removing admin permissions from the role.",
	}
}

func dataStorePolicy(role, store ontology.Node) Suggestion {
	name := sanitize(store.Name)
	content := fmt.Sprintf(`# AegisGraph auto-remediation — remove %q's access to %q.
# Tighten the resource policy / role permissions so this principal can no longer reach the data store.
resource "aws_iam_role_policy" "aegis_revoke_%s_%s" {
  name = "revoke-%s-access"
  role = %q
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*" # TODO: scope to %s's ARN
    }]
  })
}
`, role.Name, store.Name, sanitize(role.Name), name, name, role.Name, store.Name)

	return Suggestion{
		Title:     fmt.Sprintf("Revoke %s access to %s", role.Name, store.Name),
		Kind:      "terraform",
		Filename:  fmt.Sprintf("revoke-%s-%s.tf", sanitize(role.Name), name),
		Content:   content,
		Rationale: "Cuts the HAS_PERMISSION edge from the role to the crown-jewel data store.",
	}
}

func propStr(n ontology.Node, key string) string {
	s, _ := n.Properties[key].(string)
	return s
}

// sanitize makes a node name safe for use in k8s/terraform identifiers.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune('-')
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
