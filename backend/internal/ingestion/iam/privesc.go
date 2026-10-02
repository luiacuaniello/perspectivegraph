package iam

import "strings"

// actionSet is a principal's effective permissions: the Allow'd action patterns
// (e.g. "iam:AttachRolePolicy", "iam:*", "*"), each tagged with how widely it was
// granted, minus the account-wide explicit Denies, and capped by the permissions
// boundary when one is attached. It applies the parts of AWS policy evaluation that
// are unambiguous without request context - an explicit Deny always beats an Allow,
// a boundary caps to the intersection, an Allow written with NotAction grants all
// but what it names. Condition keys are not evaluated: an Allow under a condition
// counts as granted, and a Deny under one is not applied but remembered, so the
// escalation it might block is reported as depending on it. Both err toward
// reporting rather than missing.
type actionSet struct {
	grants []grant
	denies []string // account-wide Deny patterns
	// conditionalDenies are account-wide Deny patterns that apply only under a
	// Condition. Whether one holds depends on the request - MFA, source address, a tag
	// - so it is not applied, which would hide an escalation that is real whenever the
	// condition is not met; the caller reports what it might block as unverified.
	conditionalDenies []string
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
// (Resource "*" or a wildcard) rather than on specific literal resources. A grant
// written with NotAction is pattern "*" with the named actions as exceptions.
type grant struct {
	pattern string
	broad   bool
	except  []string
}

// covers reports whether the grant allows the action.
func (g grant) covers(action string) bool {
	if !matchAction(g.pattern, action) {
		return false
	}
	for _, e := range g.except {
		if matchAction(e, action) {
			return false
		}
	}
	return true
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

// addAllBut records an Allow written with NotAction: every action but those named.
func (a actionSet) addAllBut(broad bool, except []string) actionSet {
	a.grants = append(a.grants, grant{pattern: "*", broad: broad, except: append([]string(nil), except...)})
	return a
}

// deny records an account-wide explicit Deny.
func (a actionSet) deny(p string) actionSet {
	a.denies = append(a.denies, p)
	return a
}

// denyUnder records an account-wide Deny that applies only under a Condition.
func (a actionSet) denyUnder(p string) actionSet {
	a.conditionalDenies = append(a.conditionalDenies, p)
	return a
}

// conditionallyDenied reports whether a Deny the engine cannot evaluate covers the
// action: it is blocked when its condition holds and allowed when it does not.
func (a actionSet) conditionallyDenied(action string) bool {
	for _, d := range a.conditionalDenies {
		if matchAction(d, action) {
			return true
		}
	}
	return a.boundary != nil && a.boundary.conditionallyDenied(action)
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
		if g.covers(action) {
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
		if g.broad && g.covers(action) {
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
		if g.pattern == "*" && g.broad && len(g.except) == 0 {
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
	// userOnly marks a technique that works on the principal's own user or its groups.
	// A role is no user and belongs to no group, so a role holding only these actions
	// can grant power to users it cannot act as - not to itself.
	userOnly bool
}

// principalKind is what kind of principal a technique is checked for.
type principalKind int

const (
	asUser principalKind = iota
	asRole
)

// primitives is the detection table (a curated subset of the well-known AWS IAM
// privesc paths - Rhino Security Labs / PMapper). Each, if matched, means the
// principal can grant itself or assume admin-equivalent privileges.
var primitives = []primitive{
	{name: "iam:AttachRolePolicy (attach AdministratorAccess to a role)", actions: []string{"iam:AttachRolePolicy"}},
	{name: "iam:AttachUserPolicy (attach AdministratorAccess to self)", actions: []string{"iam:AttachUserPolicy"}, userOnly: true},
	{name: "iam:PutRolePolicy (inline an admin policy on a role)", actions: []string{"iam:PutRolePolicy"}},
	{name: "iam:PutUserPolicy (inline an admin policy on self)", actions: []string{"iam:PutUserPolicy"}, userOnly: true},
	{name: "iam:CreatePolicyVersion (rewrite an attached policy)", actions: []string{"iam:CreatePolicyVersion"}},
	{name: "iam:SetDefaultPolicyVersion (roll back to a permissive version)", actions: []string{"iam:SetDefaultPolicyVersion"}},
	{name: "iam:UpdateAssumeRolePolicy (make an admin role assumable)", actions: []string{"iam:UpdateAssumeRolePolicy"}},
	{name: "iam:CreateAccessKey (mint keys for a privileged user)", actions: []string{"iam:CreateAccessKey"}},
	{name: "iam:CreateLoginProfile (set a console password on a user)", actions: []string{"iam:CreateLoginProfile"}},
	{name: "iam:PassRole + lambda:CreateFunction (run code as a passed role)", actions: []string{"iam:PassRole", "lambda:CreateFunction"}},
	{name: "iam:PassRole + ec2:RunInstances (launch an instance with a passed role)", actions: []string{"iam:PassRole", "ec2:RunInstances"}},
	{name: "iam:PassRole + cloudformation:CreateStack", actions: []string{"iam:PassRole", "cloudformation:CreateStack"}},
	{name: "iam:PassRole + glue:CreateDevEndpoint", actions: []string{"iam:PassRole", "glue:CreateDevEndpoint"}},
	{name: "iam:PassRole + sagemaker:CreateNotebookInstance", actions: []string{"iam:PassRole", "sagemaker:CreateNotebookInstance"}},
	{name: "iam:PassRole + datapipeline:CreatePipeline", actions: []string{"iam:PassRole", "datapipeline:CreatePipeline"}},
	{name: "iam:PassRole + codebuild:CreateProject", actions: []string{"iam:PassRole", "codebuild:CreateProject"}},
	{name: "iam:AddUserToGroup (add self to a privileged group)", actions: []string{"iam:AddUserToGroup"}, userOnly: true},
	{name: "iam:AttachGroupPolicy (attach AdministratorAccess to your group)", actions: []string{"iam:AttachGroupPolicy"}, userOnly: true},
	{name: "iam:PutGroupPolicy (inline an admin policy on your group)", actions: []string{"iam:PutGroupPolicy"}, userOnly: true},
	{name: "iam:UpdateLoginProfile (reset a privileged user's console password)", actions: []string{"iam:UpdateLoginProfile"}},
}

// privescMatch is one matched escalation primitive and how it was granted.
type privescMatch struct {
	Name string
	// ScopedOnly means at least one action the primitive needs is held only on
	// specific resources, never account-wide. The escalation is still real, but it
	// is contingent on those resources being privileged - materially less certain
	// than an account-wide grant, so the caller scores it lower.
	ScopedOnly bool
	// Conditional means a Deny the engine cannot evaluate covers at least one action
	// the primitive needs: the escalation holds only when that condition does not.
	Conditional bool
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
	// UserOnly marks a technique that only a user can turn on itself (see AppliesTo).
	UserOnly bool
}

// AppliesTo reports whether the technique can work for the principal with this ARN. The
// user-only ones cannot work for a role, and checking them there would confirm an
// escalation the engine does not claim.
func (p PrivescPrimitive) AppliesTo(principalARN string) bool {
	return !p.UserOnly || !strings.Contains(principalARN, ":role/")
}

// PrivescPrimitives returns the detection table as data.
func PrivescPrimitives() []PrivescPrimitive {
	out := make([]PrivescPrimitive, 0, len(primitives))
	for _, p := range primitives {
		out = append(out, PrivescPrimitive{Name: p.name, Actions: append([]string(nil), p.actions...), UserOnly: p.userOnly})
	}
	return out
}

// detectPrivesc returns every privesc primitive the principal's permissions
// enable. A primitive matches when ALL its actions are allowed (explicit Deny
// already applied by actionSet.Allows), and when it can work for this kind of
// principal at all.
func detectPrivesc(a actionSet, kind principalKind) []privescMatch {
	var found []privescMatch
	for _, p := range primitives {
		if p.userOnly && kind == asRole {
			continue
		}
		allowed, broad, conditional := true, true, false
		for _, act := range p.actions {
			if !a.Allows(act) {
				allowed = false
				break
			}
			if !a.BroadlyAllows(act) {
				broad = false
			}
			if a.conditionallyDenied(act) {
				conditional = true
			}
		}
		if allowed {
			found = append(found, privescMatch{Name: p.name, ScopedOnly: !broad, Conditional: conditional})
		}
	}
	return found
}
