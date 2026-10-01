package ingestion

import "strings"

// IMDSAssumeProb is how likely a foothold on an EC2 instance becomes credentials for its
// role. With IMDSv2 enforced (HttpTokens=required) a blind SSRF cannot mint the token, so
// the attacker needs code execution first; with IMDSv1 still answering, one GET is enough.
// An instance whose setting is not in the input counts as IMDSv1, so the step is reported
// rather than missed.
//
// Every source that draws instance --ASSUMES--> role scores it here. They write the same
// edge, and when two of them scored it differently its probability depended on which one
// arrived last.
func IMDSAssumeProb(httpTokens string) float64 {
	if strings.EqualFold(httpTokens, "required") {
		return 0.6
	}
	return 0.9
}
