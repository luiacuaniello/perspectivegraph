package terraform

import (
	"encoding/json"
	"sort"
	"strings"
)

// The IAM feed, in the shape of `aws iam get-account-authorization-details`: the roles and
// users the configuration defines or attaches policies to, with their trust policies,
// inline policies, attached policies and permissions boundaries, and the managed policies
// whose documents the plan carries.

type iamBundle struct {
	UserDetailList  []iamUser   `json:"UserDetailList"`
	GroupDetailList []any       `json:"GroupDetailList"`
	RoleDetailList  []iamRole   `json:"RoleDetailList"`
	Policies        []iamPolicy `json:"Policies"`
}

type iamRole struct {
	RoleName                 string       `json:"RoleName"`
	Arn                      string       `json:"Arn"`
	AssumeRolePolicyDocument any          `json:"AssumeRolePolicyDocument"`
	AttachedManagedPolicies  []attached   `json:"AttachedManagedPolicies"`
	RolePolicyList           []inline     `json:"RolePolicyList"`
	Tags                     []tag        `json:"Tags,omitempty"`
	PermissionsBoundary      *boundaryRef `json:"PermissionsBoundary,omitempty"`
	managed                  bool         // the configuration defines it
}

type iamUser struct {
	UserName                string       `json:"UserName"`
	Arn                     string       `json:"Arn"`
	AttachedManagedPolicies []attached   `json:"AttachedManagedPolicies"`
	UserPolicyList          []inline     `json:"UserPolicyList"`
	PermissionsBoundary     *boundaryRef `json:"PermissionsBoundary,omitempty"`
	managed                 bool
}

type attached struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type inline struct {
	PolicyName     string `json:"PolicyName"`
	PolicyDocument any    `json:"PolicyDocument"`
}

type boundaryRef struct {
	Type string `json:"PermissionsBoundaryType"`
	Arn  string `json:"PermissionsBoundaryArn"`
}

type iamPolicy struct {
	PolicyName        string          `json:"PolicyName"`
	Arn               string          `json:"Arn"`
	DefaultVersionID  string          `json:"DefaultVersionId"`
	PolicyVersionList []policyVersion `json:"PolicyVersionList"`
}

type policyVersion struct {
	Document         any    `json:"Document"`
	VersionID        string `json:"VersionId"`
	IsDefaultVersion bool   `json:"IsDefaultVersion"`
}

// awsManaged are the documents of the AWS managed policies that hand out what the
// escalation table looks for, so a plan that attaches one is read as granting it. Their
// text lives in AWS, not in the plan, and these are the parts that matter here. An AWS
// managed policy not in this table is read as granting nothing - an attachment of one is
// noted, and a live read of the account (-aws-region) supplies the real document.
var awsManaged = map[string]string{
	"AdministratorAccess": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
	"IAMFullAccess":       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:*","organizations:DescribeAccount","organizations:DescribeOrganization","organizations:DescribeOrganizationalUnit","organizations:DescribePolicy","organizations:ListChildren","organizations:ListParents","organizations:ListPoliciesForTarget","organizations:ListRoots","organizations:ListPolicies","organizations:ListTargetsForPolicy"],"Resource":"*"}]}`,
	"PowerUserAccess":     `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"},{"Effect":"Allow","Action":["iam:CreateServiceLinkedRole","iam:DeleteServiceLinkedRole","iam:ListRoles","organizations:DescribeOrganization","account:ListRegions","account:GetAccountInformation"],"Resource":"*"}]}`,
}

const awsManagedPrefix = "arn:aws:iam::aws:policy/"

// iam builds the IAM feed of a view, and notes what it could not read.
func (p *Plan) iam(v View) (iamBundle, []string) {
	b := iamBundle{UserDetailList: []iamUser{}, GroupDetailList: []any{}, RoleDetailList: []iamRole{}, Policies: []iamPolicy{}}
	var notes []string
	roles := map[string]*iamRole{} // by ARN
	var roleOrder []string
	role := func(arn, name string) *iamRole {
		if r, ok := roles[arn]; ok {
			return r
		}
		r := &iamRole{RoleName: name, Arn: arn, AttachedManagedPolicies: []attached{}, RolePolicyList: []inline{}}
		roles[arn] = r
		roleOrder = append(roleOrder, arn)
		return r
	}
	users := map[string]*iamUser{}
	var userOrder []string
	user := func(arn, name string) *iamUser {
		if u, ok := users[arn]; ok {
			return u
		}
		u := &iamUser{UserName: name, Arn: arn, AttachedManagedPolicies: []attached{}, UserPolicyList: []inline{}}
		users[arn] = u
		userOrder = append(userOrder, arn)
		return u
	}
	doc := func(owner *Resource, attr, what string) (any, bool) {
		if !p.Known(v, owner, attr) {
			notes = append(notes, owner.Address+": "+what+" is known only after apply")
			return nil, false
		}
		s := p.Str(v, owner, attr)
		if s == "" {
			return nil, false
		}
		var d any
		if err := json.Unmarshal([]byte(s), &d); err != nil {
			notes = append(notes, owner.Address+": "+what+" is not valid JSON")
			return nil, false
		}
		return d, true
	}

	for _, r := range p.Resources(v, "aws_iam_role") {
		if !r.Managed() {
			continue
		}
		rr := role(p.arnOf(v, r), p.nameOf(v, r))
		rr.managed = true
		if d, ok := doc(r, "assume_role_policy", "its trust policy"); ok {
			rr.AssumeRolePolicyDocument = d
		}
		if pb := p.Str(v, r, "permissions_boundary"); pb != "" {
			rr.PermissionsBoundary = &boundaryRef{Type: "Policy", Arn: pb}
		}
		if tags, ok := r.Values["tags"].(map[string]any); ok {
			rr.Tags = tagList(tags)
		}
		// Inline policies written in the role itself are authoritative when configured;
		// unconfigured, the attribute only reflects what other resources attach.
		if cfg := p.configOf(r); cfg != nil {
			if _, configured := cfg.Expressions["inline_policy"]; configured {
				blocks, _ := r.Values["inline_policy"].([]any)
				for i := range blocks {
					name, _ := dig(r.Values, "inline_policy", i, "name")
					text, _ := dig(r.Values, "inline_policy", i, "policy")
					s, _ := text.(string)
					var d any
					if s == "" || json.Unmarshal([]byte(s), &d) != nil {
						notes = append(notes, r.Address+": an inline policy is known only after apply")
						continue
					}
					n, _ := name.(string)
					rr.RolePolicyList = append(rr.RolePolicyList, inline{PolicyName: n, PolicyDocument: d})
				}
				if unknownAt(r.Unknown, "inline_policy") {
					notes = append(notes, r.Address+": its inline policies are known only after apply")
				}
			}
			if _, configured := cfg.Expressions["managed_policy_arns"]; configured {
				for _, arn := range p.Strs(v, r, "managed_policy_arns") {
					rr.AttachedManagedPolicies = append(rr.AttachedManagedPolicies, attached{PolicyName: arn[strings.LastIndex(arn, "/")+1:], PolicyArn: arn})
				}
			}
		}
	}
	for _, r := range p.Resources(v, "aws_iam_role_policy") {
		if !r.Managed() {
			continue
		}
		target := p.Str(v, r, "role")
		if target == "" {
			notes = append(notes, r.Address+": the role it is written on is known only after apply")
			continue
		}
		rr := role(p.roleARN(v, target), roleName(target))
		if d, ok := doc(r, "policy", "its policy"); ok {
			name, _ := r.Values["name"].(string)
			rr.RolePolicyList = append(rr.RolePolicyList, inline{PolicyName: name, PolicyDocument: d})
		}
	}
	for _, r := range p.Resources(v, "aws_iam_role_policy_attachment") {
		if !r.Managed() {
			continue
		}
		target, pol := p.Str(v, r, "role"), p.Str(v, r, "policy_arn")
		if target == "" || pol == "" {
			notes = append(notes, r.Address+": what it attaches, or to which role, is known only after apply")
			continue
		}
		rr := role(p.roleARN(v, target), roleName(target))
		rr.AttachedManagedPolicies = append(rr.AttachedManagedPolicies, attached{PolicyName: pol[strings.LastIndex(pol, "/")+1:], PolicyArn: pol})
	}

	// aws_iam_policy_attachment attaches one policy to lists of roles and users at once;
	// the users' share waits for the users to be read below.
	type userAttachment struct{ user, policy string }
	var userAttachments []userAttachment
	for _, r := range p.Resources(v, "aws_iam_policy_attachment") {
		if !r.Managed() {
			continue
		}
		pol := p.Str(v, r, "policy_arn")
		if pol == "" {
			notes = append(notes, r.Address+": the policy it attaches is known only after apply")
			continue
		}
		for _, target := range p.Strs(v, r, "roles") {
			rr := role(p.roleARN(v, target), roleName(target))
			rr.AttachedManagedPolicies = append(rr.AttachedManagedPolicies, attached{PolicyName: pol[strings.LastIndex(pol, "/")+1:], PolicyArn: pol})
		}
		for _, u := range p.Strs(v, r, "users") {
			userAttachments = append(userAttachments, userAttachment{u, pol})
		}
	}

	for _, r := range p.Resources(v, "aws_iam_user") {
		if !r.Managed() {
			continue
		}
		u := user(p.arnOf(v, r), p.nameOf(v, r))
		u.managed = true
		if pb := p.Str(v, r, "permissions_boundary"); pb != "" {
			u.PermissionsBoundary = &boundaryRef{Type: "Policy", Arn: pb}
		}
	}
	userARN := func(name string) string {
		for _, r := range p.Resources(v, "aws_iam_user") {
			if p.nameOf(v, r) == name {
				return p.arnOf(v, r)
			}
		}
		return "arn:aws:iam::" + p.accountOr() + ":user/" + name
	}
	for _, r := range p.Resources(v, "aws_iam_user_policy") {
		if !r.Managed() {
			continue
		}
		name := p.Str(v, r, "user")
		if name == "" {
			continue
		}
		u := user(userARN(name), name)
		if d, ok := doc(r, "policy", "its policy"); ok {
			pn, _ := r.Values["name"].(string)
			u.UserPolicyList = append(u.UserPolicyList, inline{PolicyName: pn, PolicyDocument: d})
		}
	}
	for _, a := range userAttachments {
		u := user(userARN(a.user), a.user)
		u.AttachedManagedPolicies = append(u.AttachedManagedPolicies, attached{PolicyName: a.policy[strings.LastIndex(a.policy, "/")+1:], PolicyArn: a.policy})
	}
	for _, r := range p.Resources(v, "aws_iam_user_policy_attachment") {
		if !r.Managed() {
			continue
		}
		name, pol := p.Str(v, r, "user"), p.Str(v, r, "policy_arn")
		if name == "" || pol == "" {
			continue
		}
		u := user(userARN(name), name)
		u.AttachedManagedPolicies = append(u.AttachedManagedPolicies, attached{PolicyName: pol[strings.LastIndex(pol, "/")+1:], PolicyArn: pol})
	}

	// The managed policies: the configuration's own, and the AWS managed ones attached,
	// as far as their documents are known here.
	defined := map[string]bool{}
	for _, r := range p.Resources(v, "aws_iam_policy") {
		arn := p.arnOf(v, r)
		defined[arn] = true
		d, ok := doc(r, "policy", "its document")
		if !ok {
			continue
		}
		b.Policies = append(b.Policies, iamPolicy{PolicyName: p.nameOf(v, r), Arn: arn, DefaultVersionID: "v1",
			PolicyVersionList: []policyVersion{{Document: d, VersionID: "v1", IsDefaultVersion: true}}})
	}
	attachedARNs := map[string]bool{}
	for _, arn := range roleOrder {
		for _, a := range roles[arn].AttachedManagedPolicies {
			attachedARNs[a.PolicyArn] = true
		}
		if pb := roles[arn].PermissionsBoundary; pb != nil {
			attachedARNs[pb.Arn] = true
		}
	}
	for _, arn := range userOrder {
		for _, a := range users[arn].AttachedManagedPolicies {
			attachedARNs[a.PolicyArn] = true
		}
	}
	var awsARNs []string
	for arn := range attachedARNs {
		if strings.HasPrefix(arn, awsManagedPrefix) && !defined[arn] {
			awsARNs = append(awsARNs, arn)
		}
	}
	sort.Strings(awsARNs)
	for _, arn := range awsARNs {
		name := arn[len(awsManagedPrefix):]
		text, ok := awsManaged[name]
		if !ok {
			continue
		}
		var d any
		_ = json.Unmarshal([]byte(text), &d)
		b.Policies = append(b.Policies, iamPolicy{PolicyName: name, Arn: arn, DefaultVersionID: "v1",
			PolicyVersionList: []policyVersion{{Document: d, VersionID: "v1", IsDefaultVersion: true}}})
	}

	for _, arn := range roleOrder {
		r := roles[arn]
		if r.AssumeRolePolicyDocument == nil {
			// A role the configuration only attaches to: its trust policy lives elsewhere,
			// and an empty one trusts nobody - it adds no way in that is not there.
			r.AssumeRolePolicyDocument = map[string]any{"Statement": []any{}}
		}
		b.RoleDetailList = append(b.RoleDetailList, *r)
	}
	for _, arn := range userOrder {
		b.UserDetailList = append(b.UserDetailList, *users[arn])
	}
	return b, notes
}

// roleName takes what a role attribute holds - a name, or an ARN - to the role's name.
func roleName(s string) string {
	if strings.HasPrefix(s, "arn:") {
		return s[strings.LastIndex(s, "/")+1:]
	}
	return s
}
