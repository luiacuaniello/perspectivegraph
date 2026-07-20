package iam

import "strings"

// actionSet is a principal's effective permissions: the Allow'd action patterns
// (e.g. "iam:AttachRolePolicy", "iam:*", "*"), each tagged with how widely it was
// granted, minus the account-wide explicit Denies. It applies the parts of AWS
// policy evaluation that are unambiguous without request context - an explicit
// Deny always beats an Allow - while leaving Condition keys and NotAction out, so
// detection still errs toward over-reporting rather than missing.
type actionSet struct {
	grants []grant
	denies []string // account-wide Deny patterns
}

// grant is one Allow'd action pattern plus whether it was granted account-wide
// (Resource "*" or a wildcard) rather than on specific literal resources.
type grant struct {
	pattern string
	broad   bool
}

// add records an account-wide Allow.
func (a actionSet) add(p string) actionSet {
	a.grants = append(a.grants, grant{pattern: p, broad: true})
	return a
}

// addScoped records an Allow confined to specific literal resources.
func (a actionSet) addScoped(p string) actionSet {
	a.grants = append(a.grants, grant{pattern: p, broad: false})
	return a
}

// deny records an account-wide explicit Deny.
func (a actionSet) deny(p string) actionSet {
	a.denies = append(a.denies, p)
	return a
}

// Allows reports whether the principal may perform the action: some Allow pattern
// matches and no account-wide Deny does, honoring IAM '*' wildcards
// (case-insensitive). Explicit Deny wins, exactly as AWS evaluates it.
func (a actionSet) Allows(action string) bool {
	if a.denied(action) {
		return false
	}
	for _, g := range a.grants {
		if matchAction(g.pattern, action) {
			return true
		}
	}
	return false
}

// BroadlyAllows is Allows restricted to account-wide grants: it excludes actions
// the principal holds only on specific resources.
func (a actionSet) BroadlyAllows(action string) bool {
	if a.denied(action) {
		return false
	}
	for _, g := range a.grants {
		if g.broad && matchAction(g.pattern, action) {
			return true
		}
	}
	return false
}

// denied reports whether an account-wide explicit Deny covers the action.
func (a actionSet) denied(action string) bool {
	for _, d := range a.denies {
		if matchAction(d, action) {
			return true
		}
	}
	return false
}

// IsAdmin reports effective admin: an account-wide Allow on every action. Only a
// blanket Deny revokes it - a narrow guardrail Deny leaves a principal that can
// still do essentially everything, which is what matters for risk.
func (a actionSet) IsAdmin() bool {
	if a.denied("*") {
		return false
	}
	for _, g := range a.grants {
		if g.pattern == "*" && g.broad {
			return true
		}
	}
	return false
}

// matchAction does case-insensitive glob matching with '*' (the only wildcard
// IAM action patterns use besides '?', which we treat as a literal here).
func matchAction(pattern, action string) bool {
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == action
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(action[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false // first segment must anchor at the start
		}
		pos += idx + len(part)
	}
	// A trailing non-'*' segment must reach the end.
	if last := parts[len(parts)-1]; last != "" {
		return strings.HasSuffix(action, last)
	}
	return true
}

// primitive is a known privilege-escalation technique: the actions a principal
// must hold (ALL of them) to reach admin-equivalent access.
type primitive struct {
	name    string
	actions []string
}

// primitives is the detection table (a curated subset of the well-known AWS IAM
// privesc paths - Rhino Security Labs / PMapper). Each, if matched, means the
// principal can grant itself or assume admin-equivalent privileges.
var primitives = []primitive{
	{"iam:AttachRolePolicy (attach AdministratorAccess to a role)", []string{"iam:AttachRolePolicy"}},
	{"iam:AttachUserPolicy (attach AdministratorAccess to self)", []string{"iam:AttachUserPolicy"}},
	{"iam:PutRolePolicy (inline an admin policy on a role)", []string{"iam:PutRolePolicy"}},
	{"iam:PutUserPolicy (inline an admin policy on self)", []string{"iam:PutUserPolicy"}},
	{"iam:CreatePolicyVersion (rewrite an attached policy)", []string{"iam:CreatePolicyVersion"}},
	{"iam:SetDefaultPolicyVersion (roll back to a permissive version)", []string{"iam:SetDefaultPolicyVersion"}},
	{"iam:UpdateAssumeRolePolicy (make an admin role assumable)", []string{"iam:UpdateAssumeRolePolicy"}},
	{"iam:CreateAccessKey (mint keys for a privileged user)", []string{"iam:CreateAccessKey"}},
	{"iam:CreateLoginProfile (set a console password on a user)", []string{"iam:CreateLoginProfile"}},
	{"iam:PassRole + lambda:CreateFunction (run code as a passed role)", []string{"iam:PassRole", "lambda:CreateFunction"}},
	{"iam:PassRole + ec2:RunInstances (launch an instance with a passed role)", []string{"iam:PassRole", "ec2:RunInstances"}},
	{"iam:PassRole + cloudformation:CreateStack", []string{"iam:PassRole", "cloudformation:CreateStack"}},
	{"iam:PassRole + glue:CreateDevEndpoint", []string{"iam:PassRole", "glue:CreateDevEndpoint"}},
	{"iam:PassRole + sagemaker:CreateNotebookInstance", []string{"iam:PassRole", "sagemaker:CreateNotebookInstance"}},
	{"iam:PassRole + datapipeline:CreatePipeline", []string{"iam:PassRole", "datapipeline:CreatePipeline"}},
	{"iam:PassRole + codebuild:CreateProject", []string{"iam:PassRole", "codebuild:CreateProject"}},
	{"iam:AddUserToGroup (add self to a privileged group)", []string{"iam:AddUserToGroup"}},
	{"iam:AttachGroupPolicy (attach AdministratorAccess to your group)", []string{"iam:AttachGroupPolicy"}},
	{"iam:PutGroupPolicy (inline an admin policy on your group)", []string{"iam:PutGroupPolicy"}},
	{"iam:UpdateLoginProfile (reset a privileged user's console password)", []string{"iam:UpdateLoginProfile"}},
}

// privescMatch is one matched escalation primitive and how it was granted.
type privescMatch struct {
	Name string
	// ScopedOnly means at least one action the primitive needs is held only on
	// specific resources, never account-wide. The escalation is still real, but it
	// is contingent on those resources being privileged - materially less certain
	// than an account-wide grant, so the caller scores it lower.
	ScopedOnly bool
}

// detectPrivesc returns every privesc primitive the principal's permissions
// enable. A primitive matches when ALL its actions are allowed (explicit Deny
// already applied by actionSet.Allows).
func detectPrivesc(a actionSet) []privescMatch {
	var found []privescMatch
	for _, p := range primitives {
		allowed, broad := true, true
		for _, act := range p.actions {
			if !a.Allows(act) {
				allowed = false
				break
			}
			if !a.BroadlyAllows(act) {
				broad = false
			}
		}
		if allowed {
			found = append(found, privescMatch{Name: p.name, ScopedOnly: !broad})
		}
	}
	return found
}
