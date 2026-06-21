package iam

import "strings"

// actionSet is the flattened set of Allow'd action patterns for a principal
// (e.g. "iam:AttachRolePolicy", "iam:*", "*"). Resource/Condition scoping is
// intentionally ignored in this MVP, so detection can over-report (a permission
// scoped to one resource is treated as account-wide) but never miss the obvious
// escalation — the honest trade-off PMapper makes resource-aware.
type actionSet struct {
	patterns []string
}

func (a actionSet) add(p string) actionSet {
	a.patterns = append(a.patterns, p)
	return a
}

// Allows reports whether any granted pattern matches the queried action,
// honoring IAM '*' wildcards (case-insensitive).
func (a actionSet) Allows(action string) bool {
	for _, p := range a.patterns {
		if matchAction(p, action) {
			return true
		}
	}
	return false
}

// IsAdmin reports effective admin: a principal that can perform any action.
func (a actionSet) IsAdmin() bool {
	for _, p := range a.patterns {
		if p == "*" {
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

// primitive is a known privilege-escalation technique: a predicate over a
// principal's permissions that, if true, lets it reach admin-equivalent access.
type primitive struct {
	name  string
	match func(actionSet) bool
}

// primitives is the detection table (a curated subset of the well-known AWS IAM
// privesc paths — Rhino Security Labs / PMapper). Each, if matched, means the
// principal can grant itself or assume admin-equivalent privileges.
var primitives = []primitive{
	{"iam:AttachRolePolicy (attach AdministratorAccess to a role)", func(a actionSet) bool { return a.Allows("iam:AttachRolePolicy") }},
	{"iam:AttachUserPolicy (attach AdministratorAccess to self)", func(a actionSet) bool { return a.Allows("iam:AttachUserPolicy") }},
	{"iam:PutRolePolicy (inline an admin policy on a role)", func(a actionSet) bool { return a.Allows("iam:PutRolePolicy") }},
	{"iam:PutUserPolicy (inline an admin policy on self)", func(a actionSet) bool { return a.Allows("iam:PutUserPolicy") }},
	{"iam:CreatePolicyVersion (rewrite an attached policy)", func(a actionSet) bool { return a.Allows("iam:CreatePolicyVersion") }},
	{"iam:SetDefaultPolicyVersion (roll back to a permissive version)", func(a actionSet) bool { return a.Allows("iam:SetDefaultPolicyVersion") }},
	{"iam:UpdateAssumeRolePolicy (make an admin role assumable)", func(a actionSet) bool { return a.Allows("iam:UpdateAssumeRolePolicy") }},
	{"iam:CreateAccessKey (mint keys for a privileged user)", func(a actionSet) bool { return a.Allows("iam:CreateAccessKey") }},
	{"iam:CreateLoginProfile (set a console password on a user)", func(a actionSet) bool { return a.Allows("iam:CreateLoginProfile") }},
	{"iam:PassRole + lambda:CreateFunction (run code as a passed role)", func(a actionSet) bool { return a.Allows("iam:PassRole") && a.Allows("lambda:CreateFunction") }},
	{"iam:PassRole + ec2:RunInstances (launch an instance with a passed role)", func(a actionSet) bool { return a.Allows("iam:PassRole") && a.Allows("ec2:RunInstances") }},
	{"iam:PassRole + cloudformation:CreateStack", func(a actionSet) bool { return a.Allows("iam:PassRole") && a.Allows("cloudformation:CreateStack") }},
	{"iam:PassRole + glue:CreateDevEndpoint", func(a actionSet) bool { return a.Allows("iam:PassRole") && a.Allows("glue:CreateDevEndpoint") }},
}

// detectPrivesc returns the names of every privesc primitive the principal's
// permissions enable.
func detectPrivesc(a actionSet) []string {
	var found []string
	for _, p := range primitives {
		if p.match(a) {
			found = append(found, p.name)
		}
	}
	return found
}
