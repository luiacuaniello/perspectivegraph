package terraform

import (
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
)

// Load balancers and ECS services, in the shapes the AWS connector flattens them into the
// network feed: per load balancer its scheme, groups, subnets, the ports its listeners
// serve and the targets of the groups it forwards to; per ECS service its groups, subnets,
// public address, task role and the target groups it registers in.
//
// A load balancer forwards to a target group through a listener's default action or a
// listener rule. Targets come from aws_lb_target_group_attachment; the ones an Auto
// Scaling group or an ECS service registers are not in the plan - an ECS service's are
// read from the service, and laid over the account, a target group's live targets stay.

func (p *Plan) loadBalancers(v View, b *netBundle) []string {
	var notes []string
	lbs := map[string]*lbRecord{}
	var order []string
	lb := func(arn string) *lbRecord {
		if r, ok := lbs[arn]; ok {
			return r
		}
		r := &lbRecord{LoadBalancerArn: arn, LoadBalancerName: ingestion.LoadBalancerNameFromARN(arn), Type: lbTypeOf(arn)}
		lbs[arn] = r
		order = append(order, arn)
		return r
	}
	for _, r := range p.Resources(v, "aws_lb", "aws_alb") {
		if !r.Managed() {
			continue
		}
		arn := p.arnOf(v, r)
		rec := lb(arn)
		rec.LoadBalancerName, rec.Type = p.nameOf(v, r), p.lbType(r)
		rec.Scheme = "internet-facing"
		if internal, _ := r.Values["internal"].(bool); internal {
			rec.Scheme = "internal"
		}
		rec.IPAddressType, _ = r.Values["ip_address_type"].(string)
		rec.SecurityGroups = p.Strs(v, r, "security_groups")
		subnets := p.Strs(v, r, "subnets")
		blocks, _ := r.Values["subnet_mapping"].([]any)
		for i := range blocks {
			if sn := p.Str(v, r, "subnet_mapping", i, "subnet_id"); sn != "" {
				subnets = append(subnets, sn)
			}
		}
		for _, sn := range dedupe(subnets) {
			rec.AvailabilityZones = append(rec.AvailabilityZones, lbZone{SubnetID: sn})
		}
		if unknownAt(r.Unknown, "security_groups") && len(rec.SecurityGroups) == 0 {
			notes = append(notes, r.Address+": its security groups are known only after apply")
		}
		b.described[arn] = true
	}

	forwards := map[string][]string{} // load balancer -> target groups
	forwarded := map[[2]string]bool{} // (load balancer, target group)
	listenerLB := map[string]string{} // listener -> load balancer
	forward := func(lbArn string, tgs ...string) {
		for _, tg := range tgs {
			if k := [2]string{lbArn, tg}; tg != "" && !forwarded[k] {
				forwarded[k] = true
				forwards[lbArn] = append(forwards[lbArn], tg)
			}
		}
	}
	for _, r := range p.Resources(v, "aws_lb_listener", "aws_alb_listener") {
		if !r.Managed() {
			continue
		}
		lbArn := p.Str(v, r, "load_balancer_arn")
		if lbArn == "" {
			notes = append(notes, r.Address+": the load balancer it listens on is known only after apply")
			continue
		}
		rec := lb(lbArn)
		l := listener{Protocol: strings.ToUpper(p.Str(v, r, "protocol"))}
		if l.Protocol == "" {
			l.Protocol = "HTTP"
			if rec.Type == "network" {
				l.Protocol = "TCP"
			}
		}
		if port, ok := toInt(r.Values["port"]); ok {
			l.Port = &port
		}
		rec.Listeners = append(rec.Listeners, l)
		listenerLB[p.arnOf(v, r)] = lbArn
		forward(lbArn, p.forwardTargets(v, r, "default_action")...)
	}
	for _, r := range p.Resources(v, "aws_lb_listener_rule", "aws_alb_listener_rule") {
		if !r.Managed() {
			continue
		}
		l := p.Str(v, r, "listener_arn")
		lbArn := listenerLB[l]
		if lbArn == "" && strings.Contains(l, ":listener/") {
			lbArn = ingestion.LoadBalancerARNFromListener(l)
		}
		if lbArn == "" {
			notes = append(notes, r.Address+": the listener it adds to is known only after apply")
			continue
		}
		lb(lbArn)
		forward(lbArn, p.forwardTargets(v, r, "action")...)
	}

	tgs := map[string]*tgRecord{}
	typed := map[string]bool{} // groups the configuration defines, with their target type
	var tgOrder []string
	tg := func(arn string) *tgRecord {
		if t, ok := tgs[arn]; ok {
			return t
		}
		t := &tgRecord{TargetGroupArn: arn, TargetType: "instance", Targets: []target{}}
		tgs[arn] = t
		tgOrder = append(tgOrder, arn)
		return t
	}
	for _, r := range p.Resources(v, "aws_lb_target_group", "aws_alb_target_group") {
		if !r.Managed() {
			continue
		}
		t := tg(p.arnOf(v, r))
		typed[t.TargetGroupArn] = true
		if s, _ := r.Values["target_type"].(string); s != "" {
			t.TargetType = s
		}
		t.Protocol, _ = r.Values["protocol"].(string)
		if port, ok := toInt(r.Values["port"]); ok {
			t.Port = &port
		}
	}
	for _, r := range p.Resources(v, "aws_lb_target_group_attachment", "aws_alb_target_group_attachment") {
		if !r.Managed() {
			continue
		}
		group, id := p.Str(v, r, "target_group_arn"), p.Str(v, r, "target_id")
		if group == "" || id == "" {
			notes = append(notes, r.Address+": the target it registers, or where, is known only after apply")
			continue
		}
		t := tg(group)
		if !typed[group] {
			t.TargetType = targetTypeOf(id)
		}
		tt := target{ID: id}
		if port, ok := toInt(r.Values["port"]); ok {
			tt.Port = &port
		}
		t.Targets = append(t.Targets, tt)
	}

	attached := map[string]bool{}
	for _, arn := range order {
		rec := lbs[arn]
		for _, g := range forwards[arn] {
			rec.TargetGroups = append(rec.TargetGroups, *tg(g))
			attached[g] = true
		}
		b.LoadBalancers = append(b.LoadBalancers, *rec)
	}
	// Target groups no load balancer of the plan forwards to: their targets are laid over
	// the account's groups of the same ARN.
	for _, arn := range tgOrder {
		if !attached[arn] && len(tgs[arn].Targets) > 0 {
			b.looseGroups = append(b.looseGroups, *tgs[arn])
		}
	}
	return notes
}

// forwardTargets are the target groups an action list forwards to: a forward action's
// target group, or each group of a weighted forward.
func (p *Plan) forwardTargets(v View, r *Resource, block string) []string {
	var out []string
	actions, _ := r.Values[block].([]any)
	for i := range actions {
		if t := p.Str(v, r, block, i, "type"); t != "" && t != "forward" {
			continue
		}
		if g := p.Str(v, r, block, i, "target_group_arn"); g != "" {
			out = append(out, g)
		}
		groups, _ := dig(r.Values, block, i, "forward", 0, "target_group")
		list, _ := groups.([]any)
		for j := range list {
			if g := p.Str(v, r, block, i, "forward", 0, "target_group", j, "arn"); g != "" {
				out = append(out, g)
			}
		}
	}
	return out
}

func (p *Plan) ecsServices(v View, b *netBundle) []string {
	var notes []string
	roles := map[string]string{} // task definition ARN, and family, -> task role
	for _, r := range p.Resources(v, "aws_ecs_task_definition") {
		if !r.Managed() {
			continue
		}
		role := p.Str(v, r, "task_role_arn")
		roles[p.arnOf(v, r)] = role
		if family, _ := r.Values["family"].(string); family != "" {
			roles[family] = role
		}
	}
	for _, r := range p.Resources(v, "aws_ecs_service") {
		if !r.Managed() {
			continue
		}
		if _, ok := dig(r.Values, "network_configuration", 0); !ok {
			continue // bridge or host networking: no security groups of its own
		}
		cluster := p.Str(v, r, "cluster")
		if cluster != "" && !strings.HasPrefix(cluster, "arn:") {
			cluster = "arn:aws:ecs:" + p.regionOf(r) + ":" + p.accountOr() + ":cluster/" + cluster
		}
		svc := ecsRecord{ServiceArn: p.id(v, r), ServiceName: p.nameOf(v, r), ClusterArn: cluster,
			SecurityGroups: p.Strs(v, r, "network_configuration", 0, "security_groups"),
			Subnets:        p.Strs(v, r, "network_configuration", 0, "subnets"), AssignPublicIP: "DISABLED"}
		if pub, _ := dig(r.Values, "network_configuration", 0, "assign_public_ip"); pub == true {
			svc.AssignPublicIP = "ENABLED"
		}
		lbBlocks, _ := r.Values["load_balancer"].([]any)
		for i := range lbBlocks {
			if g := p.Str(v, r, "load_balancer", i, "target_group_arn"); g != "" {
				svc.TargetGroups = append(svc.TargetGroups, g)
			}
		}
		td := p.Str(v, r, "task_definition")
		role, found := roles[td]
		if !found {
			role, found = roles[taskFamily(td)]
		}
		svc.TaskRoleArn = role
		if !found && td != "" {
			b.unknownTask = append(b.unknownTask, r.Address+"\x00"+svc.ServiceArn+"\x00"+td)
		}
		b.ECSServices = append(b.ECSServices, svc)
	}
	return notes
}

// taskFamily is the family of a task definition named by ARN, family:revision or family.
func taskFamily(td string) string {
	if i := strings.LastIndex(td, "task-definition/"); i >= 0 {
		td = td[i+len("task-definition/"):]
	}
	if i := strings.LastIndex(td, ":"); i >= 0 {
		td = td[:i]
	}
	return td
}

// lbTypeOf reads a load balancer's type out of its ARN.
func lbTypeOf(arn string) string {
	switch {
	case strings.Contains(arn, ":loadbalancer/net/"):
		return "network"
	case strings.Contains(arn, ":loadbalancer/gwy/"):
		return "gateway"
	}
	return "application"
}

// targetTypeOf is what a registered target is, by its identifier: an instance, a function,
// another load balancer, or an address.
func targetTypeOf(id string) string {
	switch {
	case strings.HasPrefix(id, "i-"):
		return "instance"
	case strings.Contains(id, ":lambda:"):
		return "lambda"
	case strings.Contains(id, ":loadbalancer/"):
		return "alb"
	}
	return "ip"
}
