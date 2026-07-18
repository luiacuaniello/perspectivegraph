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
		if got := detectPrivesc(a); len(got) == 0 {
			t.Errorf("%s should be detected as a privesc primitive, got none", name)
		}
	}
	// A harmless permission must NOT be flagged.
	if got := detectPrivesc(actionSet{}.add("s3:GetObject")); len(got) != 0 {
		t.Errorf("s3:GetObject is not privesc, got %v", got)
	}
}
