// Package k8s discovers network-exposure and identity topology from a
// Kubernetes cluster dump and emits it as ontology relationships — the edges no
// scanner produces but every attack path needs:
//
//	Ingress ──ROUTES_TO──▶ Service ──EXPOSES──▶ Pod(Container)
//	Pod ──ASSUMES──▶ ServiceAccount ──ASSUMES──▶ Role   (crown jewel if admin)
//	Pod ──HOSTS──▶ Image   (inferred from the image ref by the normalizer)
//
// Input is the JSON of `kubectl get ingress,service,pod,serviceaccount,
// clusterrole,clusterrolebinding,rolebinding -A -o json` — a List whose items
// the collector walks by kind. This turns a real cluster into discoverable
// attack surface without hand-stitched ids.
package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "k8s" }

// ── minimal typed views of the resources we consume ─────────────────

type meta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

type item struct {
	Kind     string          `json:"kind"`
	Metadata meta            `json:"metadata"`
	Spec     json.RawMessage `json:"spec"`
	Subjects []struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"subjects"`
	RoleRef struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
	Rules []struct {
		Verbs     []string `json:"verbs"`
		Resources []string `json:"resources"`
		APIGroups []string `json:"apiGroups"`
	} `json:"rules"`
}

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	items, err := decode(r)
	if err != nil {
		return nil, err
	}

	g := &builder{nodes: map[string]ontology.Node{}}
	var pods, services, ingresses, sas, bindings []item
	adminRoles := map[string]bool{}        // role name -> wildcard-admin
	escalationRoles := map[string]string{} // role name -> escalation primitive it grants

	for _, it := range items {
		switch strings.ToLower(it.Kind) {
		case "pod":
			pods = append(pods, it)
		case "service":
			services = append(services, it)
		case "ingress":
			ingresses = append(ingresses, it)
		case "serviceaccount":
			sas = append(sas, it)
		case "rolebinding", "clusterrolebinding":
			bindings = append(bindings, it)
		case "role", "clusterrole":
			if isAdminRole(it) {
				adminRoles[it.Metadata.Name] = true
			} else if reason := escalateReason(it); reason != "" {
				// Not wildcard-admin, but grants an RBAC primitive that *becomes*
				// admin (BloodHound-for-K8s): create pods, read secrets, bind/escalate
				// roles, impersonate. The shallow "is it named admin / is it *:*" check
				// misses these.
				escalationRoles[it.Metadata.Name] = reason
			}
		}
	}

	// Index pods by namespace for service-selector matching.
	type podRef struct {
		id     string
		labels map[string]string
	}
	podsByNS := map[string][]podRef{}
	for _, p := range pods {
		var spec podSpec
		_ = json.Unmarshal(p.Spec, &spec)
		ns := nsOf(p.Metadata)
		id := ontology.NewID(ontology.LabelContainer, ns+"/"+p.Metadata.Name)
		props := map[string]any{"k8s_ns": ns, "k8s_pod": p.Metadata.Name}
		if len(spec.Containers) > 0 {
			props[ontology.PropImageRef] = spec.Containers[0].Image // normalizer infers HOSTS→Image
		}
		escape := escapeReason(spec)
		if escape != "" {
			props["k8s_escape"] = escape
		}
		g.upsert(ontology.Node{ID: id, Label: ontology.LabelContainer, Name: p.Metadata.Name, Properties: props})
		podsByNS[ns] = append(podsByNS[ns], podRef{id: id, labels: p.Metadata.Labels})

		// A host-breaking pod can escape its container to the node — and from the
		// node, the cluster (ATT&CK T1611). Model it as a direct route to cluster-admin.
		if escape != "" {
			g.edge(ontology.EdgeEscapesTo, id, clusterAdmin(g), 0.95)
		}

		// Pod assumes its ServiceAccount.
		saName := first(spec.ServiceAccountName, spec.ServiceAccount, "default")
		saID := g.stub(ontology.LabelServiceAccount, ns+"/"+saName)
		g.edge(ontology.EdgeAssumes, id, saID, 0.8)
	}

	// Services route to the pods their selector matches; LB/NodePort are exposed.
	svcID := map[string]string{} // ns/name -> node id
	for _, s := range services {
		var spec svcSpec
		_ = json.Unmarshal(s.Spec, &spec)
		ns := nsOf(s.Metadata)
		key := ns + "/" + s.Metadata.Name
		id := ontology.NewID(ontology.LabelLoadBalancer, "svc/"+key)
		props := map[string]any{"k8s_ns": ns, "k8s_kind": "Service", "k8s_service_type": spec.Type}
		if spec.Type == "LoadBalancer" || spec.Type == "NodePort" {
			props[ontology.PropInternetExposed] = true
		}
		g.upsert(ontology.Node{ID: id, Label: ontology.LabelLoadBalancer, Name: s.Metadata.Name, Properties: props})
		svcID[key] = id

		for _, pod := range podsByNS[ns] {
			if selectorMatches(spec.Selector, pod.labels) {
				g.edge(ontology.EdgeExposes, id, pod.id, 0.9)
			}
		}
	}

	// Ingress is an internet entry point routing to backend services.
	for _, in := range ingresses {
		var spec ingSpec
		_ = json.Unmarshal(in.Spec, &spec)
		ns := nsOf(in.Metadata)
		id := ontology.NewID(ontology.LabelLoadBalancer, "ing/"+ns+"/"+in.Metadata.Name)
		host := ""
		for _, rule := range spec.Rules {
			if rule.Host != "" {
				host = rule.Host
			}
		}
		g.upsert(ontology.Node{ID: id, Label: ontology.LabelLoadBalancer, Name: in.Metadata.Name,
			Properties: map[string]any{"k8s_ns": ns, "k8s_kind": "Ingress", "host": host, ontology.PropInternetExposed: true}})

		for _, rule := range spec.Rules {
			for _, path := range rule.HTTP.Paths {
				if svc := path.Backend.Service.Name; svc != "" {
					if target, ok := svcID[ns+"/"+svc]; ok {
						g.edge(ontology.EdgeRoutesTo, id, target, 0.9)
					} else {
						target := g.stub(ontology.LabelLoadBalancer, "svc/"+ns+"/"+svc)
						g.edge(ontology.EdgeRoutesTo, id, target, 0.9)
					}
				}
			}
		}
	}

	// ServiceAccounts as identity nodes.
	for _, sa := range sas {
		ns := nsOf(sa.Metadata)
		g.upsert(ontology.Node{ID: ontology.NewID(ontology.LabelServiceAccount, ns+"/"+sa.Metadata.Name),
			Label: ontology.LabelServiceAccount, Name: ns + "/" + sa.Metadata.Name,
			Properties: map[string]any{"k8s_ns": ns}})
	}

	// Bindings: a ServiceAccount assumes a Role; admin roles are crown jewels.
	for _, b := range bindings {
		roleName := b.RoleRef.Name
		isAdmin := adminRoles[roleName] || isAdminName(roleName)
		escalation := escalationRoles[roleName]
		props := map[string]any{"k8s_kind": b.RoleRef.Kind}
		if isAdmin {
			props[ontology.PropCrownJewel] = true
			props["admin"] = true
		} else if escalation != "" {
			props["k8s_escalation"] = escalation
		}
		roleID := ontology.NewID(ontology.LabelIAMRole, roleName)
		g.upsert(ontology.Node{ID: roleID, Label: ontology.LabelIAMRole, Name: roleName, Properties: props})
		// A non-admin role that grants an escalation primitive can reach cluster-admin.
		if !isAdmin && escalation != "" {
			g.edge(ontology.EdgeCanEscalateTo, roleID, clusterAdmin(g), 0.9)
		}
		for _, subj := range b.Subjects {
			if !strings.EqualFold(subj.Kind, "ServiceAccount") {
				continue
			}
			saID := g.stub(ontology.LabelServiceAccount, nsOrDefault(subj.Namespace)+"/"+subj.Name)
			g.edge(ontology.EdgeAssumes, saID, roleID, 0.8)
		}
	}

	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      g.nodeSlice(),
		Edges:      g.edges,
	}}, nil
}

// ── spec sub-views ──────────────────────────────────────────────────

type podSpec struct {
	ServiceAccountName string `json:"serviceAccountName"`
	ServiceAccount     string `json:"serviceAccount"`
	HostPID            bool   `json:"hostPID"`
	HostNetwork        bool   `json:"hostNetwork"`
	HostIPC            bool   `json:"hostIPC"`
	Volumes            []struct {
		HostPath *struct {
			Path string `json:"path"`
		} `json:"hostPath"`
	} `json:"volumes"`
	Containers []struct {
		Name            string `json:"name"`
		Image           string `json:"image"`
		SecurityContext struct {
			Privileged *bool `json:"privileged"`
		} `json:"securityContext"`
	} `json:"containers"`
}

// escapeReason reports the first host-boundary-breaking setting on a pod that
// lets a compromised container take over the node (and from a node, the cluster).
// MITRE ATT&CK T1611. Returns "" when the pod respects its container boundary.
func escapeReason(spec podSpec) string {
	for _, c := range spec.Containers {
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return "privileged container"
		}
	}
	switch {
	case spec.HostPID:
		return "hostPID"
	case spec.HostNetwork:
		return "hostNetwork"
	case spec.HostIPC:
		return "hostIPC"
	}
	for _, v := range spec.Volumes {
		if v.HostPath != nil && v.HostPath.Path != "" {
			return "hostPath mount (" + v.HostPath.Path + ")"
		}
	}
	return ""
}

type svcSpec struct {
	Type     string            `json:"type"`
	Selector map[string]string `json:"selector"`
}

type ingSpec struct {
	Rules []struct {
		Host string `json:"host"`
		HTTP struct {
			Paths []struct {
				Backend struct {
					Service struct {
						Name string `json:"name"`
					} `json:"service"`
				} `json:"backend"`
			} `json:"paths"`
		} `json:"http"`
	} `json:"rules"`
}

// ── builder + helpers ───────────────────────────────────────────────

type builder struct {
	nodes map[string]ontology.Node
	edges []ontology.Edge
}

func (b *builder) upsert(n ontology.Node) {
	if existing, ok := b.nodes[n.ID]; ok {
		for k, v := range n.Properties {
			if existing.Properties == nil {
				existing.Properties = map[string]any{}
			}
			existing.Properties[k] = v
		}
		if n.Name != "" {
			existing.Name = n.Name
		}
		b.nodes[n.ID] = existing
		return
	}
	b.nodes[n.ID] = n
}

func (b *builder) stub(label ontology.Label, name string) string {
	id := ontology.NewID(label, name)
	if _, ok := b.nodes[id]; !ok {
		b.nodes[id] = ontology.Node{ID: id, Label: label, Name: name}
	}
	return id
}

func (b *builder) edge(t ontology.EdgeType, from, to string, p float64) {
	b.edges = append(b.edges, ontology.Edge{Type: t, From: from, To: to, ExploitProbability: p})
}

func (b *builder) nodeSlice() []ontology.Node {
	out := make([]ontology.Node, 0, len(b.nodes))
	for _, n := range b.nodes {
		out = append(out, n)
	}
	return out
}

// decode accepts a List ({"items":[...]}) or a bare array of resources.
func decode(r io.Reader) ([]item, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var arr []item
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, fmt.Errorf("decode k8s array: %w", err)
		}
		return arr, nil
	}
	var list struct {
		Items []item `json:"items"`
	}
	if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
		return nil, fmt.Errorf("decode k8s list: %w", err)
	}
	return list.Items, nil
}

// selectorMatches reports whether labels is a superset of selector (and the
// selector is non-empty — an empty selector matches nothing, like K8s).
func selectorMatches(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// isAdminRole detects a wildcard (verbs=* resources=*) RBAC rule.
func isAdminRole(it item) bool {
	for _, rule := range it.Rules {
		if contains(rule.Verbs, "*") && contains(rule.Resources, "*") {
			return true
		}
	}
	return false
}

func isAdminName(name string) bool {
	n := strings.ToLower(name)
	return n == "cluster-admin" || strings.Contains(n, "admin")
}

// escalateReason reports the first RBAC privilege-escalation primitive a (non
// wildcard-admin) role grants — the verb/resource combos that let a workload
// bootstrap itself to cluster-admin. Returns "" when the role is benign.
func escalateReason(it item) string {
	for _, r := range it.Rules {
		switch {
		case anyOf(r.Verbs, "escalate", "*") && anyOf(r.Resources, "roles", "clusterroles", "*"):
			return "roles/escalate"
		case anyOf(r.Verbs, "bind", "*") && anyOf(r.Resources, "rolebindings", "clusterrolebindings", "roles", "clusterroles", "*"):
			return "rolebindings/bind"
		case anyOf(r.Verbs, "impersonate", "*") && anyOf(r.Resources, "users", "groups", "serviceaccounts", "*"):
			return "impersonate"
		case anyOf(r.Verbs, "create", "*") && anyOf(r.Resources, "pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "replicasets"):
			return "workloads/create" // run an arbitrary image as any mounted SA
		case anyOf(r.Verbs, "get", "list", "watch", "*") && anyOf(r.Resources, "secrets"):
			return "secrets/read" // read every secret in scope (token/credential theft)
		case anyOf(r.Verbs, "create", "*") && anyOf(r.Resources, "serviceaccounts/token", "tokenrequests"):
			return "serviceaccounts/token" // mint tokens for any SA
		}
	}
	return ""
}

func anyOf(have []string, want ...string) bool {
	for _, h := range have {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}

// clusterAdmin ensures the synthetic K8s cluster-admin crown jewel exists (full
// cluster control), the target every escalation primitive reaches — the K8s
// analogue of the IAM collector's account-admin.
func clusterAdmin(g *builder) string {
	id := ontology.NewID(ontology.LabelIAMRole, "perspectivegraph:cluster-admin")
	g.upsert(ontology.Node{ID: id, Label: ontology.LabelIAMRole, Name: "cluster-admin (effective)",
		Properties: map[string]any{ontology.PropCrownJewel: true, "admin": true, "k8s_synthetic": true}})
	return id
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func nsOf(m meta) string { return nsOrDefault(m.Namespace) }
func nsOrDefault(ns string) string {
	if ns == "" {
		return "default"
	}
	return ns
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
