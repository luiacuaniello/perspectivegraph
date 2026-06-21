// Package remediation turns an attack path into concrete "cut an edge"
// artifacts. The insight from the analyzer is that breaking *any* single edge
// of a path neutralizes it — so instead of demanding every finding be fixed,
// PerspectiveGraph proposes the cheapest cut: isolate the exposed workload with a
// Kubernetes NetworkPolicy, scope down an over-broad IAM role, or tighten a
// data store's access, generated as ready-to-review code.
package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Suggestion is one generated remediation artifact.
type Suggestion struct {
	Title     string `json:"title"`
	Kind      string `json:"kind"`      // "k8s-networkpolicy" | "terraform"
	Filename  string `json:"filename"`  // suggested file name
	Content   string `json:"content"`   // the artifact body (YAML/HCL)
	Rationale string `json:"rationale"` // which edge it cuts and why
	// Cut is the graph edge this artifact severs, in structured form, so the API
	// can *verify* the fix by simulating its removal (what-if) instead of trusting
	// the generator's word — the closed loop, "we proved it cuts the path".
	Cut CutEdge `json:"cut"`
}

// CutEdge identifies the edge a remediation severs (node ids + edge type).
type CutEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// Rule matches one step of a path and builds the artifact that cuts it. New
// remediations are added by appending to Registry — no switch to edit, and the
// API and the PR commenter automatically pick them up.
type Rule struct {
	Name  string
	Match func(step analyzer.Step, from, to ontology.Node) bool
	Build func(from, to ontology.Node) Suggestion
}

func edgeIn(t ontology.EdgeType, set ...ontology.EdgeType) bool {
	for _, s := range set {
		if t == s {
			return true
		}
	}
	return false
}

// Registry is the ordered rule set Generate consults.
var Registry = []Rule{
	{
		Name: "isolate-container",
		Match: func(st analyzer.Step, _, to ontology.Node) bool {
			return edgeIn(st.EdgeType, ontology.EdgeExposes, ontology.EdgeRoutesTo, ontology.EdgeHosts) &&
				to.Label == ontology.LabelContainer
		},
		Build: func(_, to ontology.Node) Suggestion { return networkPolicy(to) },
	},
	{
		Name: "restrict-public-ingress",
		Match: func(st analyzer.Step, from, to ontology.Node) bool {
			return edgeIn(st.EdgeType, ontology.EdgeExposes, ontology.EdgeRoutesTo, ontology.EdgeHosts) &&
				to.Label == ontology.LabelVirtualMachine && from.Label == ontology.LabelLoadBalancer
		},
		Build: func(from, to ontology.Node) Suggestion { return sgRevoke(from, to) },
	},
	{
		Name: "scope-down-admin-role",
		Match: func(st analyzer.Step, _, to ontology.Node) bool {
			return st.EdgeType == ontology.EdgeAssumes &&
				to.Label == ontology.LabelIAMRole && to.Bool(ontology.PropCrownJewel)
		},
		Build: func(_, to ontology.Node) Suggestion { return iamScopeDown(to) },
	},
	{
		Name: "revoke-datastore-access",
		Match: func(st analyzer.Step, _, to ontology.Node) bool {
			return st.EdgeType == ontology.EdgeHasPermission &&
				(to.Label == ontology.LabelBucket || to.Label == ontology.LabelDatabase)
		},
		Build: func(from, to ontology.Node) Suggestion { return dataStorePolicy(from, to) },
	},
	{
		// IAM privilege escalation: deny the escalation primitives on the source
		// principal so it can no longer reach admin-equivalent access.
		Name: "block-privilege-escalation",
		Match: func(st analyzer.Step, from, _ ontology.Node) bool {
			return st.EdgeType == ontology.EdgeCanEscalateTo &&
				(from.Label == ontology.LabelIAMRole || from.Label == ontology.LabelUser)
		},
		Build: func(from, _ ontology.Node) Suggestion { return privescDeny(from) },
	},
	{
		// Cloud lateral movement: cut the discovered reachability between two
		// instances (SG-to-SG ingress) so the source can no longer reach the target.
		Name: "segment-lateral-reachability",
		Match: func(st analyzer.Step, _, _ ontology.Node) bool {
			return st.EdgeType == ontology.EdgeConnectsTo
		},
		Build: func(from, to ontology.Node) Suggestion { return networkSegment(from, to) },
	},
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
	for _, st := range p.Steps {
		from, to := index[st.From], index[st.To]
		for _, rule := range Registry {
			if !rule.Match(st, from, to) {
				continue
			}
			s := rule.Build(from, to)
			// The artifact cuts the matched step's edge; record it so the fix is
			// verifiable by simulating that exact removal.
			s.Cut = CutEdge{From: st.From, To: st.To, Type: string(st.EdgeType)}
			key := s.Kind + "|" + s.Filename
			if !seen[key] {
				seen[key] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// ── Choke-point remediation optimizer ───────────────────────────────
//
// Many critical paths share a few edges. Cutting one such edge neutralizes
// every path through it, so the question that matters is not "what are the 50
// paths" but "what is the smallest set of fixes that eliminates the most risk".
// Plan answers it: a weighted greedy set-cover over the artifacts the Registry
// would generate, where a path's weight is its exploit score.

// Fix is one remediation ranked by the share of critical-path risk it removes.
// In a Plan the fixes partition the paths: PathsCut/RiskCovered/CoveragePct are
// the *marginal* contribution at this position, so coverage sums monotonically.
type Fix struct {
	Suggestion  Suggestion
	PathsCut    []string // attack-path ids this fix is credited with eliminating
	PathCount   int
	RiskCovered float64 // sum of those paths' scores (absolute risk removed)
	CoveragePct float64 // RiskCovered / total critical-path risk, in [0,1]
}

// Plan ranks remediations so the top entries are the fewest fixes that
// neutralize the most critical-path risk. Paths a fix shares with an
// earlier-picked fix are credited to the earlier one, so the list reads as an
// ordered "do these in order" plan with cumulative coverage.
func Plan(paths []analyzer.AttackPath) []Fix {
	// fix key -> the suggestion, and the set of path indices it breaks.
	sugg := map[string]Suggestion{}
	breaks := map[string]map[int]bool{}
	totalRisk := 0.0
	for i, p := range paths {
		totalRisk += p.Score
		for _, s := range Generate(p) {
			key := s.Kind + "|" + s.Filename
			if _, ok := sugg[key]; !ok {
				sugg[key] = s
			}
			if breaks[key] == nil {
				breaks[key] = map[int]bool{}
			}
			breaks[key][i] = true
		}
	}

	covered := make([]bool, len(paths))
	var plan []Fix
	for len(breaks) > 0 {
		// Pick the fix removing the most still-uncovered risk; ties → most
		// paths, then smallest key, for deterministic output.
		keys := make([]string, 0, len(breaks))
		for k := range breaks {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		bestKey, bestRisk, bestCount := "", 0.0, 0
		for _, key := range keys {
			risk, count := 0.0, 0
			for i := range breaks[key] {
				if !covered[i] {
					risk += paths[i].Score
					count++
				}
			}
			if risk > bestRisk || (risk == bestRisk && count > bestCount) {
				bestKey, bestRisk, bestCount = key, risk, count
			}
		}
		if bestKey == "" || bestRisk == 0 {
			break // nothing left to cover
		}

		var ids []string
		for i := range breaks[bestKey] {
			if !covered[i] {
				covered[i] = true
				ids = append(ids, paths[i].ID)
			}
		}
		sort.Strings(ids)
		cov := 0.0
		if totalRisk > 0 {
			cov = bestRisk / totalRisk
		}
		plan = append(plan, Fix{
			Suggestion:  sugg[bestKey],
			PathsCut:    ids,
			PathCount:   len(ids),
			RiskCovered: bestRisk,
			CoveragePct: cov,
		})
		delete(breaks, bestKey)
	}
	return plan
}

// HintRule renders a one-line, human-readable fix hint for a finding node on
// the path (used by the PR commenter alongside the generated artifacts).
type HintRule struct {
	Label  ontology.Label
	Render func(n ontology.Node) string
}

// HintRegistry maps finding labels to hint renderers.
var HintRegistry = []HintRule{
	{ontology.LabelCVE, func(n ontology.Node) string {
		if fv := propStr(n, "fixed_version"); fv != "" {
			return fmt.Sprintf("Upgrade the affected dependency to `%s` to remediate **%s**.", fv, n.Name)
		}
		return fmt.Sprintf("Patch or remove the dependency affected by **%s**.", n.Name)
	}},
	{ontology.LabelWeakness, func(n ontology.Node) string {
		msg := propStr(n, "message")
		if msg == "" {
			msg = "Fix the flagged code weakness"
		}
		return msg + location(n)
	}},
	{ontology.LabelSecret, func(n ontology.Node) string {
		return fmt.Sprintf("Rotate the exposed credential and remove it%s; load it from a secret manager instead.", location(n))
	}},
}

// Hints returns one fix hint per finding node on the path, in path order.
func Hints(p analyzer.AttackPath) []string {
	var out []string
	for _, n := range p.Nodes {
		for _, h := range HintRegistry {
			if n.Label == h.Label {
				out = append(out, h.Render(n))
			}
		}
	}
	return out
}

func location(n ontology.Node) string {
	path := propStr(n, "path")
	if path == "" {
		return ""
	}
	if line, ok := n.Properties["line"].(float64); ok && line > 0 {
		return fmt.Sprintf(" (`%s:%d`)", path, int(line))
	}
	if line, ok := n.Properties["line"].(int); ok && line > 0 {
		return fmt.Sprintf(" (`%s:%d`)", path, line)
	}
	return fmt.Sprintf(" (`%s`)", path)
}

func networkPolicy(c ontology.Node) Suggestion {
	app := sanitize(c.Name)
	ns := propStr(c, "k8s_ns")
	if ns == "" {
		ns = "default"
	}
	content := fmt.Sprintf(`# PerspectiveGraph auto-remediation — isolate %q to cut the ingress edge.
# Review and scope the ingress rules to only the senders this workload needs.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: perspective-deny-ingress-%s
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
	content := fmt.Sprintf(`# PerspectiveGraph auto-remediation — remove the public ingress fronting %q (via %q).
# Replace the 0.0.0.0/0 rule on the relevant security group with your trusted CIDRs.
resource "aws_security_group_rule" "perspective_restrict_%s" {
  type              = "ingress"
  description       = "Restricted by PerspectiveGraph (was 0.0.0.0/0)"
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
	content := fmt.Sprintf(`# PerspectiveGraph auto-remediation — scope down over-privileged role %q.
# Detach the broad managed policy and attach a least-privilege one:
#   aws iam detach-role-policy --role-name %s --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
resource "aws_iam_role_policy" "perspective_least_privilege_%s" {
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
	content := fmt.Sprintf(`# PerspectiveGraph auto-remediation — remove %q's access to %q.
# Tighten the resource policy / role permissions so this principal can no longer reach the data store.
resource "aws_iam_role_policy" "perspective_revoke_%s_%s" {
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

// privescDeny attaches a deny policy on the well-known IAM privilege-escalation
// actions to the source principal — apply-ready: it needs only the principal's
// name (no placeholders). A public-trust role gets an extra note to fix its
// trust policy, the other half of why it is reachable.
func privescDeny(p ontology.Node) Suggestion {
	name := sanitize(p.Name)
	resourceType, attr := "aws_iam_role_policy", "role"
	kind := "role"
	if p.Label == ontology.LabelUser {
		resourceType, attr, kind = "aws_iam_user_policy", "user", "user"
	}
	trustNote := ""
	if p.Bool(ontology.PropInternetExposed) {
		trustNote = fmt.Sprintf(
			"\n# NOTE: %q is publicly assumable (trust policy allows Principal \"*\").\n"+
				"# Also restrict its AssumeRolePolicyDocument to the principals that truly need it.\n",
			p.Name)
	}
	content := fmt.Sprintf(`# PerspectiveGraph auto-remediation — neutralize the privilege-escalation
# primitive on %s %q so it can no longer reach admin-equivalent access.%s
resource "%s" "perspective_block_privesc_%s" {
  name = "%s-block-privesc"
  %s = %q
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PerspectiveGraphDenyPrivesc"
      Effect   = "Deny"
      Action   = [
        "iam:PassRole", "iam:AttachRolePolicy", "iam:AttachUserPolicy",
        "iam:PutRolePolicy", "iam:PutUserPolicy", "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion", "iam:UpdateAssumeRolePolicy",
        "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"
      ]
      Resource = "*"
    }]
  })
}
`, kind, p.Name, trustNote, resourceType, name, name, attr, p.Name)

	return Suggestion{
		Title:     "Block privilege escalation for " + p.Name,
		Kind:      "terraform",
		Filename:  "block-privesc-" + name + ".tf",
		Content:   content,
		Rationale: "Cuts the CAN_ESCALATE_TO edge by denying the IAM actions (PassRole, Attach*/Put* policy, CreatePolicyVersion…) that let this principal escalate to admin.",
	}
}

// networkSegment cuts the discovered lateral reachability (a CONNECTS_TO edge,
// typically an SG-to-SG ingress) between two assets.
func networkSegment(from, to ontology.Node) Suggestion {
	a, z := sanitize(from.Name), sanitize(to.Name)
	content := fmt.Sprintf(`# PerspectiveGraph auto-remediation — cut lateral reachability %q -> %q.
# A security-group rule lets %q reach %q. Remove the SG-to-SG ingress (or VPC
# peering) that admits it; if some access is required, scope it to the exact
# ports/protocols instead of the whole security group.
resource "aws_security_group_rule" "perspective_segment_%s_to_%s" {
  type                     = "ingress"
  description              = "Tightened by PerspectiveGraph: %s should not freely reach %s"
  security_group_id        = "REPLACE_WITH_%s_SG_ID"
  source_security_group_id = "REPLACE_WITH_%s_SG_ID"
  protocol                 = "tcp"
  from_port                = 0    # TODO: only the ports this dependency needs
  to_port                  = 0
}
`, from.Name, to.Name, from.Name, to.Name, a, z, from.Name, to.Name, z, a)

	return Suggestion{
		Title:     fmt.Sprintf("Segment %s ↛ %s", from.Name, to.Name),
		Kind:      "terraform",
		Filename:  fmt.Sprintf("segment-%s-%s.tf", a, z),
		Content:   content,
		Rationale: "Cuts the CONNECTS_TO edge by removing the security-group reachability the attacker would use for lateral movement.",
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
