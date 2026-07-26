package iam

import "strings"

// actionSet is a principal's effective permissions: the Allow'd action patterns
// (e.g. "iam:AttachRolePolicy", "iam:*", "*"), each tagged with how widely it was
// granted, minus the account-wide explicit Denies, and capped by the permissions
// boundary when one is attached. It applies the parts of AWS policy evaluation that
// are unambiguous without request context - an explicit Deny always beats an Allow,
// a boundary caps to the intersection - while leaving Condition keys and NotAction
// out, so detection still errs toward over-reporting rather than missing.
type actionSet struct {
	grants []grant
	denies []string // account-wide Deny patterns
	// boundary is the permissions boundary's own action set, or nil when no boundary
	// applies. It never grants anything on its own: AWS evaluates a boundary purely as
	// a cap, so effective permission is the INTERSECTION of the identity policies and
	// the boundary, and a boundary alone leaves a principal able to do nothing.
	boundary *actionSet
	// boundaryUnresolved records that a boundary IS attached but its document was not
	// in the input, so the cap cannot be computed. The set then evaluates as if
	// uncapped - a boundary of AdministratorAccess is a common no-op, and dropping the
	// permission would miss it - and the caller scores the claim down instead of
	// passing it off as verified.
	boundaryUnresolved bool
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

// cappedBy applies a permissions boundary: the principal's effective permissions
// become the intersection of what its identity policies allow and what the boundary
// allows. No explicit Deny is involved - a boundary that simply omits an action
// removes it - which is how boundaries are used in practice and exactly the case a
// reader of identity policies alone gets wrong.
//
// The boundary is stored stripped of any boundary of its own: a boundary policy is
// an ordinary managed policy and is not itself bounded.
func (a actionSet) cappedBy(boundary actionSet) actionSet {
	boundary.boundary, boundary.boundaryUnresolved = nil, false
	a.boundary, a.boundaryUnresolved = &boundary, false
	return a
}

// cappedByUnknown records a boundary whose policy document the input did not carry.
// We know the principal is capped but not by how much, so the set keeps evaluating
// uncapped (the over-report bias) and flags itself, letting the caller report the
// escalation as unverified rather than as established.
func (a actionSet) cappedByUnknown() actionSet {
	a.boundary, a.boundaryUnresolved = nil, true
	return a
}

// Allows reports whether the principal may perform the action: some Allow pattern
// matches, no account-wide Deny does, and the permissions boundary (if any) also
// permits it - honoring IAM '*' wildcards (case-insensitive). Explicit Deny wins and
// a boundary caps, exactly as AWS evaluates them.
func (a actionSet) Allows(action string) bool {
	if a.denied(action) || !a.boundaryAllows(action) {
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
// the principal holds only on specific resources. A boundary that permits the action
// only on specific resources narrows it the same way, so the result is broad only if
// both sides of the intersection are.
func (a actionSet) BroadlyAllows(action string) bool {
	if a.denied(action) || !a.boundaryBroadlyAllows(action) {
		return false
	}
	for _, g := range a.grants {
		if g.broad && matchAction(g.pattern, action) {
			return true
		}
	}
	return false
}

// boundaryAllows reports whether the permissions boundary lets the action through.
// No boundary (including one we could not resolve) caps nothing.
func (a actionSet) boundaryAllows(action string) bool {
	return a.boundary == nil || a.boundary.Allows(action)
}

// boundaryBroadlyAllows is boundaryAllows restricted to account-wide boundary grants.
func (a actionSet) boundaryBroadlyAllows(action string) bool {
	return a.boundary == nil || a.boundary.BroadlyAllows(action)
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
// still do essentially everything, which is what matters for risk. A permissions
// boundary that is not itself admin-equivalent does revoke it: the intersection is
// then strictly smaller than the account, however broad the identity policy reads.
func (a actionSet) IsAdmin() bool {
	if a.denied("*") {
		return false
	}
	if a.boundary != nil && !a.boundary.IsAdmin() {
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

// PrivescPrimitive is one escalation technique exposed for callers that must check
// the SAME techniques against an external authority - notably the red-team oracle,
// which asks AWS whether a principal really holds them. Exported so there is one
// list rather than two: a second copy would drift, and a drifted copy would grade
// the engine against techniques the engine does not actually detect.
type PrivescPrimitive struct {
	Name string
	// Actions are ALL required: a principal holds this primitive only if every one
	// of them is permitted.
	Actions []string
}

// PrivescPrimitives returns the detection table as data.
func PrivescPrimitives() []PrivescPrimitive {
	out := make([]PrivescPrimitive, 0, len(primitives))
	for _, p := range primitives {
		out = append(out, PrivescPrimitive{Name: p.name, Actions: append([]string(nil), p.actions...)})
	}
	return out
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
