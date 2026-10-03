package ingestion

import (
	"strings"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// LoadBalancerID keys a load balancer the way every collector that names one must: by
// name, account and Region, which together are unique. Cloud Custodian, the network feed
// and API Gateway's private integrations all reach the same node through it. The account
// is the one given, or else the ARN's.
func LoadBalancerID(account, arn, name string) string {
	if account == "" {
		account = AccountFromARN(arn)
	}
	return RegionalID(ontology.LabelLoadBalancer, account, RegionFromARN(arn), name)
}

// LoadBalancerNameFromARN reads a load balancer's name out of its ARN or one of its
// listeners': arn:aws:elasticloadbalancing:REGION:ACCOUNT:loadbalancer/app/NAME/ID, or
// …:listener/app/NAME/ID/LISTENER.
func LoadBalancerNameFromARN(arn string) string {
	for _, kind := range []string{":loadbalancer/", ":listener/"} {
		if _, rest, ok := strings.Cut(arn, kind); ok {
			parts := strings.Split(rest, "/")
			if len(parts) >= 3 {
				return parts[1]
			}
			return parts[0]
		}
	}
	return ""
}

// LoadBalancerARNFromListener is the ARN of the load balancer a listener belongs to.
func LoadBalancerARNFromListener(arn string) string {
	prefix, rest, ok := strings.Cut(arn, ":listener/")
	if !ok {
		return arn
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 3 {
		return arn
	}
	return prefix + ":loadbalancer/" + strings.Join(parts[:3], "/")
}
