package ingestion

import "strings"

// AccountFromARN pulls the account id out of an ARN
// (arn:partition:service:region:ACCOUNT:resource), returning "" for anything that does
// not have one - AWS-managed policies (arn:aws:iam::aws:policy/…) carry the literal
// "aws" there, and service-linked shapes can leave it empty, so this must not guess.
func AccountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return ""
	}
	if acct := parts[4]; acct != "" && acct != "aws" {
		return acct
	}
	return ""
}
