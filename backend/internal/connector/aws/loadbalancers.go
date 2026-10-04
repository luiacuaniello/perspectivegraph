package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

// elbAPI is the slice of Elastic Load Balancing v2 the connector reads: the load balancers,
// their listeners, the target groups and what is registered in them. All of it is inside
// SecurityAudit (elasticloadbalancing:Describe*).
type elbAPI interface {
	DescribeLoadBalancers(context.Context, *elb.DescribeLoadBalancersInput, ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error)
	DescribeListeners(context.Context, *elb.DescribeListenersInput, ...func(*elb.Options)) (*elb.DescribeListenersOutput, error)
	DescribeTargetGroups(context.Context, *elb.DescribeTargetGroupsInput, ...func(*elb.Options)) (*elb.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(context.Context, *elb.DescribeTargetHealthInput, ...func(*elb.Options)) (*elb.DescribeTargetHealthOutput, error)
}

// loadBalancerJSON is one load balancer with its listeners and target groups flattened in,
// the cloudnet bundle's load_balancers shape.
type loadBalancerJSON struct {
	LoadBalancerArn   string            `json:"LoadBalancerArn"`
	LoadBalancerName  string            `json:"LoadBalancerName"`
	Type              string            `json:"Type"`
	Scheme            string            `json:"Scheme"`
	IPAddressType     string            `json:"IpAddressType,omitempty"`
	SecurityGroups    []string          `json:"SecurityGroups,omitempty"`
	AvailabilityZones []lbZoneJSON      `json:"AvailabilityZones,omitempty"`
	Listeners         []lbListenerJSON  `json:"Listeners,omitempty"`
	TargetGroups      []targetGroupJSON `json:"TargetGroups,omitempty"`
}

type lbZoneJSON struct {
	SubnetID string `json:"SubnetId"`
}

type lbListenerJSON struct {
	Protocol string `json:"Protocol"`
	Port     *int   `json:"Port,omitempty"`
}

type targetGroupJSON struct {
	TargetGroupArn string       `json:"TargetGroupArn"`
	TargetType     string       `json:"TargetType"`
	Protocol       string       `json:"Protocol,omitempty"`
	Port           *int         `json:"Port,omitempty"`
	Targets        []targetJSON `json:"Targets"`
}

type targetJSON struct {
	ID   string `json:"Id"`
	Port *int   `json:"Port,omitempty"`
}

// loadBalancers reads every application, network and gateway load balancer in the region:
// its scheme, groups and subnets, the ports its listeners serve, and the targets of the
// target groups it forwards to. A target group names the load balancers that use it, so
// one pass over the groups serves every load balancer.
func (t *sdkTransport) loadBalancers(ctx context.Context) ([]loadBalancerJSON, error) {
	if t.elb == nil {
		return nil, nil
	}
	var out []loadBalancerJSON
	index := map[string]int{} // load balancer ARN -> position in out
	var marker *string
	for {
		page, err := t.elb.DescribeLoadBalancers(ctx, &elb.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("describe load balancers: %w", err)
		}
		for _, lb := range page.LoadBalancers {
			j := loadBalancerJSON{LoadBalancerArn: aws.ToString(lb.LoadBalancerArn), LoadBalancerName: aws.ToString(lb.LoadBalancerName),
				Type: string(lb.Type), Scheme: string(lb.Scheme), IPAddressType: string(lb.IpAddressType), SecurityGroups: lb.SecurityGroups}
			for _, az := range lb.AvailabilityZones {
				if s := aws.ToString(az.SubnetId); s != "" {
					j.AvailabilityZones = append(j.AvailabilityZones, lbZoneJSON{SubnetID: s})
				}
			}
			var lmarker *string
			for {
				ls, err := t.elb.DescribeListeners(ctx, &elb.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn, Marker: lmarker})
				if err != nil {
					return nil, fmt.Errorf("listeners of %s: %w", j.LoadBalancerName, err)
				}
				for _, l := range ls.Listeners {
					j.Listeners = append(j.Listeners, lbListenerJSON{Protocol: string(l.Protocol), Port: intPtr(l.Port)})
				}
				if ls.NextMarker == nil {
					break
				}
				lmarker = ls.NextMarker
			}
			index[j.LoadBalancerArn] = len(out)
			out = append(out, j)
		}
		if page.NextMarker == nil {
			break
		}
		marker = page.NextMarker
	}
	if len(out) == 0 {
		return nil, nil
	}

	marker = nil
	for {
		page, err := t.elb.DescribeTargetGroups(ctx, &elb.DescribeTargetGroupsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("describe target groups: %w", err)
		}
		for _, tg := range page.TargetGroups {
			j := targetGroupJSON{TargetGroupArn: aws.ToString(tg.TargetGroupArn), TargetType: string(tg.TargetType),
				Protocol: string(tg.Protocol), Port: intPtr(tg.Port), Targets: []targetJSON{}}
			health, err := t.elb.DescribeTargetHealth(ctx, &elb.DescribeTargetHealthInput{TargetGroupArn: tg.TargetGroupArn})
			if err != nil {
				return nil, fmt.Errorf("targets of %s: %w", j.TargetGroupArn, err)
			}
			for _, h := range health.TargetHealthDescriptions {
				if h.Target != nil && aws.ToString(h.Target.Id) != "" {
					j.Targets = append(j.Targets, targetJSON{ID: aws.ToString(h.Target.Id), Port: intPtr(h.Target.Port)})
				}
			}
			for _, lbArn := range tg.LoadBalancerArns {
				if i, ok := index[lbArn]; ok {
					out[i].TargetGroups = append(out[i].TargetGroups, j)
				}
			}
		}
		if page.NextMarker == nil {
			break
		}
		marker = page.NextMarker
	}
	return out, nil
}

func intPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}
