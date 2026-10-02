package ingestion

import (
	"strings"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

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

// RegionFromARN pulls the Region out of an ARN (arn:partition:service:REGION:…), returning
// "" for a global resource (IAM, S3) or anything that is not an ARN.
func RegionFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	return parts[3]
}

// RegionFromZone is the Region an availability zone belongs to: eu-west-1a is in eu-west-1.
// It returns "" for anything that does not end in a zone letter.
func RegionFromZone(zone string) string {
	if n := len(zone); n > 1 && zone[n-1] >= 'a' && zone[n-1] <= 'z' && zone[n-2] >= '0' && zone[n-2] <= '9' {
		return zone[:n-1]
	}
	return ""
}

// RegionalID is the node id of an AWS resource whose name is unique only per account and
// Region - an RDS instance identifier, a load balancer's name. With the Region unknown it
// is the account-scoped id, so an export that carries no Region keeps the ids it had.
func RegionalID(label ontology.Label, account, region, name string) string {
	if region == "" {
		return ontology.ScopedID(label, account, name)
	}
	return ontology.ScopedID(label, account, "region="+region, name)
}
