// Package k8s discovers network-exposure and identity topology from a
// Kubernetes cluster dump and emits it as ontology relationships - the edges no
// scanner produces but every attack path needs:
//
//	Ingress ──ROUTES_TO──▶ Service ──EXPOSES──▶ Pod(Container)
//	Pod ──ASSUMES──▶ ServiceAccount ──ASSUMES──▶ Role   (crown jewel if admin)
//	Pod ──HOSTS──▶ Image   (inferred from the image ref by the normalizer)
//
// and, on EKS, the edges between the cluster and the AWS account around it (OWASP
// Kubernetes Top 10, K08 cluster-to-cloud lateral movement):
//
//	ServiceAccount ──ASSUMES──▶ IAM role         (IRSA: eks.amazonaws.com/role-arn)
//	Pod ──ESCAPES_TO──▶ its node's EC2 instance   (whose instance role is one IMDS call away)
//	IAM role/user ──ASSUMES──▶ cluster role       (kube-system/aws-auth mapRoles/mapUsers)
//
// Input is the JSON of `kubectl get ingress,service,pod,serviceaccount,role,
// clusterrole,rolebinding,clusterrolebinding,node -A -o json` plus, on EKS,
// `kubectl get configmap aws-auth -n kube-system -o json` - a List whose items
// the collector walks by kind. This turns a real cluster into discoverable
// attack surface without hand-stitched ids. The AWS objects are keyed as the AWS
// feeds key them - roles and users by ARN, instances by account (send the dump with
// ?account=) and instance ID - so the cluster's routes continue into the account's.
//
// Names in Kubernetes are unique only within their scope, and the ids follow it. A Role
// belongs to a namespace, so it is keyed with its namespace: keyed on its name alone, a
// harmless "deployer" in one namespace became the same node as a "deployer" that can
// create pods in another, and inherited its route to cluster-admin. Everything in a dump
// belongs to one cluster, and a dump sent with ?cluster= is keyed with it: two clusters'
// prod/web-sa used to be one node, so a route could enter one cluster and end in the
// other's cluster-admin. Without ?cluster= the ids are the ones a single-cluster estate
// always had. Users and named groups belong to a directory, not to a cluster, and are
// shared across clusters on purpose.
package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "k8s" }

// ── minimal typed views of the resources we consume ─────────────────

type meta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

type item struct {
	Kind     string            `json:"kind"`
	Metadata meta              `json:"metadata"`
	Spec     json.RawMessage   `json:"spec"`
	Data     map[string]string `json:"data"` // a ConfigMap's: aws-auth's mapRoles and mapUsers
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

func (c *Collector) Parse(r io.Reader, opts ingestion.Options) ([]ontology.Event, error) {
	items, err := decode(r)
	if err != nil {
		return nil, err
	}

	// The PR context, when CI sends one. It is carried onto the objects this dump
	// CONTAINS - see builder.stamp for why not onto the ones it merely mentions.
	g := &builder{nodes: map[string]ontology.Node{}, stamp: opts.PRProps(), cluster: opts.Cluster}
	var pods, services, ingresses, sas, bindings []item
	var awsAuth *item
	nodeInstance := map[string]string{}    // Kubernetes node name -> the EC2 instance it runs on
	adminRoles := map[string]bool{}        // role name -> wildcard-admin
	escalationRoles := map[string]string{} // role name -> escalation primitive it grants
	// Roles the dump DEFINES, as opposed to the ones its bindings merely name. Only the
	// first kind belongs to the pull request that rendered it: `cluster-admin` is shipped
	// by Kubernetes, every escalation ends there, and stamping it would put the commit on
	// every route in the cluster.
	definedRoles := map[string]bool{}

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
		case "node":
			var spec struct {
				ProviderID string `json:"providerID"`
			}
			if err := decodeSpec("Node", it.Metadata, it.Spec, &spec); err != nil {
				return nil, err
			}
			if id := ec2InstanceID(spec.ProviderID); id != "" {
				nodeInstance[it.Metadata.Name] = id
			}
		case "configmap":
			if it.Metadata.Name == "aws-auth" && it.Metadata.Namespace == "kube-system" {
				awsAuth = &it
			}
		case "role", "clusterrole":
			key := roleKey(it.Kind, it.Metadata.Namespace, it.Metadata.Name)
			definedRoles[key] = true
			if isAdminRole(it) {
				adminRoles[key] = true
			} else if reason := escalateReason(it); reason != "" {
				// Not wildcard-admin, but grants an RBAC primitive that *becomes*
				// admin (BloodHound-for-K8s): create pods, read secrets, bind/escalate
				// roles, impersonate. The shallow "is it named admin / is it *:*" check
				// misses these.
				escalationRoles[key] = reason
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
		if err := decodeSpec("Pod", p.Metadata, p.Spec, &spec); err != nil {
			return nil, err
		}
		ns := nsOf(p.Metadata)
		id := g.id(ontology.LabelContainer, ns+"/"+p.Metadata.Name)
		props := map[string]any{"k8s_ns": ns, "k8s_pod": p.Metadata.Name}
		if len(spec.Containers) > 0 {
			props[ontology.PropImageRef] = spec.Containers[0].Image // normalizer infers HOSTS→Image
		}
		escape := escapeReason(spec)
		if escape != "" {
			props["k8s_escape"] = escape
		}
		g.own(ontology.Node{ID: id, Label: ontology.LabelContainer, Name: p.Metadata.Name, Properties: props})
		podsByNS[ns] = append(podsByNS[ns], podRef{id: id, labels: p.Metadata.Labels})

		// A host-breaking pod can escape its container to the node - and from the
		// node, the cluster (ATT&CK T1611). Model it as a direct route to cluster-admin.
		// On EKS the node is an EC2 instance, and the role it runs with is one IMDS call
		// away from whoever holds it: the escape continues into the account, through the
		// instance node the AWS feeds draw (and its ASSUMES edge to that role).
		if escape != "" {
			g.edge(ontology.EdgeEscapesTo, id, clusterAdmin(g), 0.95)
			if instance := nodeInstance[spec.NodeName]; instance != "" {
				vm := ontology.ScopedID(ontology.LabelVirtualMachine, opts.Account, instance)
				g.cloud(ontology.Node{ID: vm, Label: ontology.LabelVirtualMachine, Name: instance,
					Properties: map[string]any{"k8s_node": spec.NodeName}})
				g.edge(ontology.EdgeEscapesTo, id, vm, 0.95)
			}
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
		if err := decodeSpec("Service", s.Metadata, s.Spec, &spec); err != nil {
			return nil, err
		}
		ns := nsOf(s.Metadata)
		key := ns + "/" + s.Metadata.Name
		id := g.id(ontology.LabelLoadBalancer, "svc/"+key)
		props := map[string]any{"k8s_ns": ns, "k8s_kind": "Service", "k8s_service_type": spec.Type}
		if spec.Type == "LoadBalancer" || spec.Type == "NodePort" {
			props[ontology.PropInternetExposed] = true
		}
		g.own(ontology.Node{ID: id, Label: ontology.LabelLoadBalancer, Name: s.Metadata.Name, Properties: props})
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
		if err := decodeSpec("Ingress", in.Metadata, in.Spec, &spec); err != nil {
			return nil, err
		}
		ns := nsOf(in.Metadata)
		id := g.id(ontology.LabelLoadBalancer, "ing/"+ns+"/"+in.Metadata.Name)
		host := ""
		for _, rule := range spec.Rules {
			if rule.Host != "" {
				host = rule.Host
			}
		}
		g.own(ontology.Node{ID: id, Label: ontology.LabelLoadBalancer, Name: in.Metadata.Name,
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

	// ServiceAccounts as identity nodes. Index them by namespace so a Group
	// subject (system:serviceaccounts[:<ns>]) can be expanded to the real SAs it
	// covers - and thus to the pods that mount them.
	saByNS := map[string][]string{}
	var allSAs []string
	for _, sa := range sas {
		ns := nsOf(sa.Metadata)
		saID := g.id(ontology.LabelServiceAccount, ns+"/"+sa.Metadata.Name)
		saProps := map[string]any{"k8s_ns": ns}
		roleARN := strings.TrimSpace(sa.Metadata.Annotations[irsaAnnotation])
		if roleARN != "" {
			saProps["irsa_role"] = roleARN
		}
		g.own(ontology.Node{ID: saID,
			Label: ontology.LabelServiceAccount, Name: ns + "/" + sa.Metadata.Name,
			Properties: saProps})
		saByNS[ns] = append(saByNS[ns], saID)
		allSAs = append(allSAs, saID)
		// IRSA: a pod running as this ServiceAccount is handed a token it trades for the
		// annotated IAM role - the cluster's identity continues into the account's.
		if roleARN != "" {
			g.edge(ontology.EdgeAssumes, saID, g.awsPrincipal(roleARN), irsaAssumeProb)
		}
	}

	// Bindings: a ServiceAccount assumes a Role; admin roles are crown jewels. The roles
	// each group and user is bound to in THIS cluster are kept for aws-auth below: its
	// mappings hold in this cluster only, while group and user nodes are shared across
	// clusters on purpose.
	groupRoles, userRoles := map[string][]string{}, map[string][]string{}
	for _, b := range bindings {
		roleName := b.RoleRef.Name
		key := roleKey(b.RoleRef.Kind, b.Metadata.Namespace, roleName)
		isAdmin := adminRoles[key] || isAdminName(roleName)
		escalation := escalationRoles[key]
		props := map[string]any{"k8s_kind": b.RoleRef.Kind}
		if isAdmin {
			props[ontology.PropCrownJewel] = true
			props["admin"] = true
		} else if escalation != "" {
			props["k8s_escalation"] = escalation
		}
		roleID := g.id(ontology.LabelIAMRole, key)
		role := ontology.Node{ID: roleID, Label: ontology.LabelIAMRole, Name: key, Properties: props}
		if definedRoles[key] {
			g.own(role)
		} else {
			g.upsert(role)
		}
		// A non-admin role that grants an escalation primitive can reach cluster-admin,
		// weighted by how reliably that specific primitive actually gets there (not all
		// are equal - see escalationProb).
		if !isAdmin && escalation != "" {
			g.edge(ontology.EdgeCanEscalateTo, roleID, clusterAdmin(g), escalationProb(escalation))
		}
		for _, subj := range b.Subjects {
			switch strings.ToLower(subj.Kind) {
			case "serviceaccount":
				saID := g.stub(ontology.LabelServiceAccount, nsOrDefault(subj.Namespace)+"/"+subj.Name)
				g.edge(ontology.EdgeAssumes, saID, roleID, 0.8)
			case "group":
				// Binding a group to a powerful role is a common, dangerous misconfig
				// the ServiceAccount-only view used to miss entirely.
				bindGroup(g, subj.Name, roleID, saByNS, allSAs)
				groupRoles[subj.Name] = append(groupRoles[subj.Name], roleID)
			case "user":
				// A named user (e.g. an OIDC identity) has no cluster-visible workload
				// to pin it to a pod, but record the grant so the privesc stays visible.
				// Not `own`: the dump contains the binding, not the person. An OIDC
				// identity belongs to a directory, not to the commit that granted it.
				uid := ontology.NewID(ontology.LabelUser, "user/"+subj.Name)
				g.upsert(ontology.Node{ID: uid, Label: ontology.LabelUser, Name: "user:" + subj.Name,
					Properties: map[string]any{"k8s_user": subj.Name}})
				g.edge(ontology.EdgeAssumes, uid, roleID, 0.8)
				userRoles[subj.Name] = append(userRoles[subj.Name], roleID)
			}
		}
	}

	if awsAuth != nil {
		if err := mapAWSAuth(g, *awsAuth, groupRoles, userRoles); err != nil {
			return nil, err
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
	NodeName           string `json:"nodeName"`
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
			Privileged   *bool `json:"privileged"`
			Capabilities struct {
				Add []string `json:"add"`
			} `json:"capabilities"`
		} `json:"securityContext"`
	} `json:"containers"`
}

// dangerousCaps are Linux capabilities that, added to a container, let it break
// the host boundary even without privileged:true - so a `capabilities.add` that
// includes one is effectively an escape (CISA/NSA hardening guidance treats
// SYS_ADMIN as privileged-equivalent). Keyed without the CAP_ prefix, uppercase.
var dangerousCaps = map[string]bool{
	"SYS_ADMIN":       true, // mount, cgroups, the classic release_agent escape (~= privileged)
	"SYS_MODULE":      true, // load a kernel module -> arbitrary code on the host
	"SYS_PTRACE":      true, // trace/inject into processes (host procs with hostPID)
	"SYS_RAWIO":       true, // raw device I/O -> read/write host disk & memory
	"SYS_BOOT":        true, // reboot / kexec the node
	"DAC_READ_SEARCH": true, // read any host file (open_by_handle_at, the "shocker" escape)
	"DAC_OVERRIDE":    true, // bypass file permission checks
	"BPF":             true, // load eBPF programs into the host kernel
}

// decodeSpec reads one resource's spec, and refuses rather than shrugging.
//
// These three unmarshals used to be `_ = json.Unmarshal(...)`, and the shrug was the
// dangerous part: a spec that failed to parse left the struct at its zero value, so the
// pod got no image_ref (its image's CVEs never joined the graph), escapeReason saw
// nothing (T1611 container escape never fired), its ServiceAccount fell back to
// "default", and a Service lost its type so it was never marked internet-exposed. Every
// one of those makes the estate look SAFER than it is - a node that is present, plausible
// and quietly wrong, which is worse than a node that is missing.
//
// The outer decode in this same file has always returned its error. This makes the inner
// one agree: an operator gets a message naming the resource, instead of a graph that
// silently stopped seeing part of the cluster.
func decodeSpec(kind string, m meta, raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return nil // absent spec is not malformed - nothing to read
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("decode %s %s/%s spec: %w", kind, nsOf(m), m.Name, err)
	}
	return nil
}

// dangerousCap returns the first host-boundary-breaking capability in an added
// set (or "ALL"), normalized without the CAP_ prefix; "" when the set is benign.
func dangerousCap(added []string) string {
	for _, c := range added {
		n := strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		if n == "ALL" || dangerousCaps[n] {
			return n
		}
	}
	return ""
}

// escapeReason reports the first host-boundary-breaking setting on a pod that
// lets a compromised container take over the node (and from a node, the cluster).
// MITRE ATT&CK T1611. Returns "" when the pod respects its container boundary.
func escapeReason(spec podSpec) string {
	for _, c := range spec.Containers {
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return "privileged container"
		}
		if dc := dangerousCap(c.SecurityContext.Capabilities.Add); dc != "" {
			return "added capability " + dc
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
	// stamp is the pull request's identity (repo_slug / commit_sha / pr), or nil when
	// the dump arrived without one - a live cluster snapshot, say, which belongs to no
	// commit. It is applied by `own`, never by `upsert` or `stub`, because the gate asks
	// "is this commit on a path" and answers by looking for exactly these properties:
	// stamping a node the dump only REFERENCES (a ServiceAccount named by a binding, the
	// synthetic cluster-admin every escalation ends at) would put the commit on routes it
	// has nothing to do with, and a gate that is red for everything is a gate nobody reads.
	stamp map[string]any
	// cluster is the cluster the dump describes (?cluster=), "" for an estate of one.
	cluster string
}

// id is a node id inside this dump's cluster. With no cluster named it is exactly the id
// it always was, so an estate of one cluster keeps its nodes - and its route ids - as they
// were.
func (b *builder) id(label ontology.Label, key string) string {
	return ingestion.KubeID(label, b.cluster, key)
}

// own records a node this dump actually contains, stamped with the pull request that
// rendered it when there is one.
func (b *builder) own(n ontology.Node) {
	if len(b.stamp) > 0 {
		if n.Properties == nil {
			n.Properties = map[string]any{}
		}
		for k, v := range b.stamp {
			n.Properties[k] = v
		}
	}
	b.upsert(n)
}

func (b *builder) upsert(n ontology.Node) {
	if b.cluster != "" && n.Label != ontology.LabelUser {
		if n.Properties == nil {
			n.Properties = map[string]any{}
		}
		n.Properties["k8s_cluster"] = b.cluster
	}
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

// cloud records an AWS object the dump refers to - an IAM principal, an EC2 instance. It
// belongs to the account, not the cluster: no cluster stamp, and keyed as the AWS feeds
// key it, so the two meet.
func (b *builder) cloud(n ontology.Node) {
	if existing, ok := b.nodes[n.ID]; ok {
		for k, v := range n.Properties {
			if existing.Properties == nil {
				existing.Properties = map[string]any{}
			}
			existing.Properties[k] = v
		}
		b.nodes[n.ID] = existing
		return
	}
	b.nodes[n.ID] = n
}

// awsPrincipal is the node of the IAM role or user with this ARN, keyed by ARN as the iam
// collector keys it.
func (b *builder) awsPrincipal(arn string) string {
	label, name := ontology.LabelIAMRole, arn[strings.LastIndex(arn, "/")+1:]
	if strings.Contains(arn, ":user/") {
		label = ontology.LabelUser
	}
	id := ontology.NewID(label, arn)
	b.cloud(ontology.Node{ID: id, Label: label, Name: name, Properties: map[string]any{ontology.PropARN: arn}})
	return id
}

func (b *builder) stub(label ontology.Label, name string) string {
	id := b.id(label, name)
	if _, ok := b.nodes[id]; !ok {
		b.upsert(ontology.Node{ID: id, Label: label, Name: name})
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
// selector is non-empty - an empty selector matches nothing, like K8s).
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
// wildcard-admin) role grants - the verb/resource combos that let a workload
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

// escalationProb weights the CAN_ESCALATE_TO edge by how RELIABLY the primitive
// actually reaches cluster-admin - not all are equal, and treating them uniformly is
// what left the score with no resolution (a real-topology calibration finding: it
// scored a genuinely-exploitable secrets/read path the same as a bind path that
// Kubernetes' own anti-privilege-escalation blocks). `bind` on rolebindings is the
// notorious false positive: creating a binding to a role you don't hold is refused
// unless you also have `bind` on the *target* role, which this shallow check can't
// see - so it is weighted well below the primitives that just work (escalate,
// impersonate, secret/token theft). This gives the path score the resolution to
// separate a real escalation from an over-reported one.
// EscalationProb is how reliably an RBAC escalation primitive reaches cluster-admin, for
// the sources that grant one outside RBAC objects - an EKS access policy, say - so they
// weigh it as this collector does.
func EscalationProb(reason string) float64 { return escalationProb(reason) }

func escalationProb(reason string) float64 {
	switch reason {
	case "roles/escalate":
		return 0.9 // the `escalate` verb exists precisely to grant beyond your own perms
	case "impersonate":
		return 0.85 // impersonate a cluster-admin user/SA - reliable
	case "secrets/read":
		return 0.85 // read every SA token in scope -> impersonate admins
	case "serviceaccounts/token":
		return 0.85 // mint a token for any SA
	case "workloads/create":
		return 0.6 // run a pod as a mounted SA / a node-mounting pod - usually works, but PodSecurity/OPA can block
	case "rolebindings/bind":
		return 0.4 // often blocked by k8s anti-privesc (needs `bind` on the target role) - the common false positive
	default:
		return 0.7
	}
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

// bindGroup wires an RBAC Group subject to a role. Kubernetes' built-in
// serviceaccount groups (system:serviceaccounts and system:serviceaccounts:<ns>)
// expand to real workload identities - and thus to concrete pod attack paths -
// so every covered ServiceAccount gets the grant. system:authenticated widens it
// to every token holder (modeled as every SA, the pod-reachable subset);
// system:unauthenticated / system:anonymous means no credentials at all, so the
// role becomes reachable straight from the internet. A named (e.g. OIDC) group
// has no cluster-visible membership, so it is recorded as a standalone principal
// so the grant is at least visible in the graph.
func bindGroup(g *builder, group, roleID string, saByNS map[string][]string, allSAs []string) {
	switch {
	case group == "system:serviceaccounts", group == "system:authenticated":
		for _, saID := range allSAs {
			g.edge(ontology.EdgeAssumes, saID, roleID, 0.8)
		}
	case strings.HasPrefix(group, "system:serviceaccounts:"):
		ns := strings.TrimPrefix(group, "system:serviceaccounts:")
		for _, saID := range saByNS[ns] {
			g.edge(ontology.EdgeAssumes, saID, roleID, 0.8)
		}
	case group == "system:unauthenticated", group == "system:anonymous":
		// Anonymous access is a setting of one cluster's API server, unlike a named group.
		anon := g.id(ontology.LabelUser, "group/"+group)
		g.upsert(ontology.Node{ID: anon, Label: ontology.LabelUser, Name: group,
			Properties: map[string]any{ontology.PropInternetExposed: true, "k8s_group": group}})
		g.edge(ontology.EdgeAssumes, anon, roleID, 0.9)
	default:
		grp := ontology.NewID(ontology.LabelUser, "group/"+group)
		g.upsert(ontology.Node{ID: grp, Label: ontology.LabelUser, Name: "group:" + group,
			Properties: map[string]any{"k8s_group": group}})
		g.edge(ontology.EdgeAssumes, grp, roleID, 0.8)
	}
}

// clusterAdmin ensures the synthetic K8s cluster-admin crown jewel exists (full
// cluster control), the target every escalation primitive reaches - the K8s
// analogue of the IAM collector's account-admin.
func clusterAdmin(g *builder) string {
	id := g.id(ontology.LabelIAMRole, "perspectivegraph:cluster-admin")
	name := "cluster-admin (effective)"
	if g.cluster != "" {
		name = "cluster-admin (effective, " + g.cluster + ")"
	}
	g.upsert(ontology.Node{ID: id, Label: ontology.LabelIAMRole, Name: name,
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

// roleKey is a role's identity within its cluster. A Role is namespaced - "deployer" in
// ci and "deployer" in web are two roles, with whatever rules each has - so it is keyed
// "namespace/name", which no ClusterRole name can be (a name cannot contain "/"). A
// ClusterRole, or a reference that does not say (the old default), is keyed on its name.
func roleKey(kind, namespace, name string) string {
	if strings.EqualFold(kind, "Role") {
		return nsOrDefault(namespace) + "/" + name
	}
	return name
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

// irsaAnnotation is how a ServiceAccount names the IAM role its pods assume (IRSA).
const irsaAnnotation = "eks.amazonaws.com/role-arn"

// irsaAssumeProb is a pod's token traded for the role: the projected token is mounted in
// the pod, and AssumeRoleWithWebIdentity is one call. The role's trust policy must admit
// this ServiceAccount for it to work; the annotation is how the cluster says it does.
const irsaAssumeProb = 0.9

// awsAuthAssumeProb is an IAM identity mapped in aws-auth becoming its cluster identity:
// `aws eks get-token` with its credentials, against an API endpoint that is public by
// default.
const awsAuthAssumeProb = 0.9

// ec2InstanceID reads the EC2 instance a node runs on out of its providerID
// (aws:///eu-west-1a/i-0abc…), or "" for a node elsewhere.
func ec2InstanceID(providerID string) string {
	if !strings.HasPrefix(providerID, "aws://") {
		return ""
	}
	last := providerID[strings.LastIndex(providerID, "/")+1:]
	if !strings.HasPrefix(last, "i-") {
		return ""
	}
	return last
}

// awsAuthEntry is one mapping in aws-auth: an IAM role or user, and the cluster user and
// groups it authenticates as.
type awsAuthEntry struct {
	RoleARN  string   `yaml:"rolearn"`
	UserARN  string   `yaml:"userarn"`
	Username string   `yaml:"username"`
	Groups   []string `yaml:"groups"`
}

// mapAWSAuth draws the way from the AWS account into the cluster: each IAM role or user
// aws-auth maps assumes the cluster roles its groups and username are bound to here, and
// system:masters is cluster-admin outright. It links to the roles directly rather than
// through the group nodes, which are shared across clusters: a mapping holds in the
// cluster whose aws-auth says it, and through a shared group it would have reached the
// bindings of every cluster.
//
// aws-auth names a role without its IAM path, so a role created under a path
// (arn:aws:iam::1:role/team/deploy) is read here as role/deploy and does not meet the
// node the iam collector draws for it.
func mapAWSAuth(g *builder, cm item, groupRoles, userRoles map[string][]string) error {
	var entries []awsAuthEntry
	for _, key := range []string{"mapRoles", "mapUsers"} {
		raw := strings.TrimSpace(cm.Data[key])
		if raw == "" {
			continue
		}
		var part []awsAuthEntry
		if err := yaml.Unmarshal([]byte(raw), &part); err != nil {
			return fmt.Errorf("decode kube-system/aws-auth %s: %w", key, err)
		}
		entries = append(entries, part...)
	}
	for _, e := range entries {
		arn := first(e.RoleARN, e.UserARN)
		if arn == "" {
			continue
		}
		principal := g.awsPrincipal(arn)
		targets := map[string]bool{}
		for _, grp := range e.Groups {
			if grp == "system:masters" {
				targets[clusterAdmin(g)] = true
				continue
			}
			for _, r := range groupRoles[grp] {
				targets[r] = true
			}
		}
		for _, r := range userRoles[e.Username] {
			targets[r] = true
		}
		ids := make([]string, 0, len(targets))
		for id := range targets {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			g.edge(ontology.EdgeAssumes, principal, id, awsAuthAssumeProb)
		}
	}
	return nil
}
