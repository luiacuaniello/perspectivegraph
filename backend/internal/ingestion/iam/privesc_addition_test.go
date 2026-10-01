package iam

import "testing"

// TestDetectPrivescRhinoCompleteness covers the primitives added to fill the Rhino matrix.
func TestDetectPrivescRhinoCompleteness(t *testing.T) {
	cases := map[string]actionSet{
		"iam:AddUserToGroup":                              actionSet{}.add("iam:AddUserToGroup"),
		"iam:AttachGroupPolicy":                           actionSet{}.add("iam:AttachGroupPolicy"),
		"iam:PutGroupPolicy":                              actionSet{}.add("iam:PutGroupPolicy"),
		"iam:UpdateLoginProfile":                          actionSet{}.add("iam:UpdateLoginProfile"),
		"iam:PassRole + sagemaker:CreateNotebookInstance": actionSet{}.add("iam:PassRole").add("sagemaker:CreateNotebookInstance"),
		"iam:PassRole + datapipeline:CreatePipeline":      actionSet{}.add("iam:PassRole").add("datapipeline:CreatePipeline"),
		"iam:PassRole + codebuild:CreateProject":          actionSet{}.add("iam:PassRole").add("codebuild:CreateProject"),
	}
	for name, a := range cases {
		if got := detectPrivesc(a, asUser); len(got) == 0 {
			t.Errorf("%s should be detected as a privesc primitive, got none", name)
		}
	}
	// A harmless permission must NOT be flagged.
	if got := detectPrivesc(actionSet{}.add("s3:GetObject"), asUser); len(got) != 0 {
		t.Errorf("s3:GetObject is not privesc, got %v", got)
	}
}

// Five techniques work only on the principal's own user or its groups. A role is no user
// and belongs to no group, so holding one of them alone lets it grant power to users it
// cannot act as - not escalate. The engine credited roles with them at 0.9, and AWS's
// simulator could not catch it: the permission really is allowed. A user holding the
// same permission still escalates, and a role that can also act as a user (by minting
// its keys) still does, through that technique.
func TestUserTechniquesDoNotMakeARoleEscalate(t *testing.T) {
	policy := func(actions string) string {
		return `[{"PolicyName":"p","PolicyDocument":{"Statement":[{"Effect":"Allow","Action":[` + actions + `],"Resource":"*"}]}}]`
	}
	for _, act := range []string{"iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AddUserToGroup",
		"iam:AttachGroupPolicy", "iam:PutGroupPolicy"} {
		_, edges := parseRoles(t, `{
		  "RoleDetailList": [{"RoleName":"role","Arn":"arn:aws:iam::1:role/role","RolePolicyList":`+policy(`"`+act+`"`)+`}],
		  "UserDetailList": [{"UserName":"user","Arn":"arn:aws:iam::1:user/user","UserPolicyList":`+policy(`"`+act+`"`)+`}]}`)
		if e, ok := edges["role"]; ok {
			t.Errorf("a role holding only %s cannot use it on itself; got an escalation at p=%.2f (%v)",
				act, e.ExploitProbability, e.Properties["primitives"])
		}
		if _, ok := edges["user"]; !ok {
			t.Errorf("a user holding %s escalates", act)
		}
	}

	_, edges := parseRoles(t, `{"RoleDetailList": [{"RoleName":"role","Arn":"arn:aws:iam::1:role/role",
	  "RolePolicyList":`+policy(`"iam:AttachUserPolicy","iam:CreateAccessKey"`)+`}]}`)
	e, ok := edges["role"]
	if !ok {
		t.Fatal("a role that can mint a user's keys escalates")
	}
	if got := e.Properties["primitives"]; got != "iam:CreateAccessKey (mint keys for a privileged user)" {
		t.Errorf("primitives = %q, want only the technique a role can use", got)
	}
}
