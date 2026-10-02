// Package eks reads the EKS side of a cluster's access: which IAM roles the cluster's pods
// get out as (EKS Pod Identity) and which IAM principals get in, as what (access entries).
// Neither lives in the cluster's own objects - both are EKS API state - so a dump of the
// cluster cannot show them, and the routes between the cluster and its account broke at
// exactly the step OWASP's Kubernetes Top 10 names K08, cluster-to-cloud lateral movement.
//
//	ServiceAccount ──ASSUMES──▶ IAM role          (a Pod Identity association)
//	IAM role/user ──ASSUMES──▶ cluster-admin      (AmazonEKSClusterAdminPolicy)
//	IAM role/user ──ASSUMES──▶ admin/edit access ──CAN_ESCALATE_TO──▶ cluster-admin
//
// Input is an EKS bundle - per cluster, its Pod Identity associations and its access
// entries with their associated access policies, in the EKS API's own field names - as
// the AWS connector assembles it, or as one assembles it from `aws eks
// describe-pod-identity-association` and `aws eks list-associated-access-policies`.
//
// The Kubernetes objects are keyed with the cluster's name, the way the k8s collector keys
// a dump sent with ?cluster=: send each cluster's dump with ?cluster=<its EKS name>, or the
// two will not meet. The AWS principals are keyed by ARN, as the iam collector keys them.
// An access entry's kubernetesGroups are not read yet: what a group may do lives in the
// cluster's bindings, in another source, and joining them across clusters is the mistake
// aws-auth is read to avoid.
package eks

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type bundle struct {
	Clusters []cluster `json:"clusters"`
}

type cluster struct {
	Name                    string `json:"name"`
	PodIdentityAssociations []struct {
		Namespace      string `json:"namespace"`
		ServiceAccount string `json:"serviceAccount"`
		RoleArn        string `json:"roleArn"`
	} `json:"podIdentityAssociations"`
	AccessEntries []struct {
		PrincipalArn   string `json:"principalArn"`
		AccessPolicies []struct {
			PolicyArn   string `json:"policyArn"`
			AccessScope struct {
				Type string `json:"type"` // cluster | namespace
			} `json:"accessScope"`
		} `json:"accessPolicies"`
	} `json:"accessEntries"`
}

// The probabilities of each step: a pod's Pod Identity credentials are handed to it by
// the node's agent on request, and an access entry's principal turns its AWS credentials
// into a cluster token with `aws eks get-token`, against an endpoint public by default.
const (
	podIdentityAssumeProb = 0.9
	accessEntryAssumeProb = 0.9
)

// writingPolicies are the access policies that grant the Kubernetes "admin" or "edit"
// role: both read secrets - every service account token in scope - which the k8s
// collector weighs as a way to cluster-admin.
var writingPolicies = map[string]bool{"AmazonEKSAdminPolicy": true, "AmazonEKSEditPolicy": true}

type Collector struct{}

func New() *Collector             { return &Collector{} }
func (*Collector) Source() string { return "eks" }

func (c *Collector) Parse(r io.Reader, _ ingestion.Options) ([]ontology.Event, error) {
	var b bundle
	if err := json.NewDecoder(r).Decode(&b); err != nil {
		return nil, fmt.Errorf("decode eks bundle: %w", err)
	}
	g := &graph{nodes: map[string]ontology.Node{}}
	for _, cl := range b.Clusters {
		if cl.Name == "" {
			return nil, fmt.Errorf("eks bundle: a cluster without a name cannot be joined to its dump")
		}
		for _, a := range cl.PodIdentityAssociations {
			if a.Namespace == "" || a.ServiceAccount == "" || a.RoleArn == "" {
				continue
			}
			key := a.Namespace + "/" + a.ServiceAccount
			sa := ingestion.KubeID(ontology.LabelServiceAccount, cl.Name, key)
			g.add(ontology.Node{ID: sa, Label: ontology.LabelServiceAccount, Name: key, Properties: map[string]any{
				"k8s_ns": a.Namespace, "k8s_cluster": cl.Name, "pod_identity_role": a.RoleArn}})
			g.edge(ontology.EdgeAssumes, sa, g.principal(a.RoleArn), podIdentityAssumeProb)
		}
		for _, e := range cl.AccessEntries {
			if e.PrincipalArn == "" {
				continue
			}
			principal := g.principal(e.PrincipalArn)
			for _, p := range e.AccessPolicies {
				policy := p.PolicyArn[strings.LastIndex(p.PolicyArn, "/")+1:]
				switch {
				case policy == "AmazonEKSClusterAdminPolicy":
					g.edge(ontology.EdgeAssumes, principal, g.clusterAdmin(cl.Name), accessEntryAssumeProb)
				case writingPolicies[policy]:
					scope := first(strings.ToLower(p.AccessScope.Type), "cluster")
					key := "eks-access-policy/" + policy + "/" + scope
					access := ingestion.KubeID(ontology.LabelIAMRole, cl.Name, key)
					g.add(ontology.Node{ID: access, Label: ontology.LabelIAMRole, Name: policy + " (" + scope + ")",
						Properties: map[string]any{"k8s_cluster": cl.Name, "k8s_escalation": "secrets/read"}})
					g.edge(ontology.EdgeAssumes, principal, access, accessEntryAssumeProb)
					g.edge(ontology.EdgeCanEscalateTo, access, g.clusterAdmin(cl.Name), k8s.EscalationProb("secrets/read"))
				}
			}
		}
	}
	return []ontology.Event{{
		Source:     c.Source(),
		Kind:       ontology.KindRelationship,
		ObservedAt: time.Now().UTC(),
		Nodes:      g.slice(),
		Edges:      g.edges,
	}}, nil
}

type graph struct {
	nodes map[string]ontology.Node
	edges []ontology.Edge
}

func (g *graph) add(n ontology.Node) {
	if existing, ok := g.nodes[n.ID]; ok {
		for k, v := range n.Properties {
			existing.Properties[k] = v
		}
		g.nodes[n.ID] = existing
		return
	}
	g.nodes[n.ID] = n
}

func (g *graph) edge(t ontology.EdgeType, from, to string, p float64) {
	g.edges = append(g.edges, ontology.Edge{Type: t, From: from, To: to, ExploitProbability: p})
}

// principal is the IAM role or user with this ARN, keyed as the iam collector keys it.
func (g *graph) principal(arn string) string {
	label := ontology.LabelIAMRole
	if strings.Contains(arn, ":user/") {
		label = ontology.LabelUser
	}
	id := ontology.NewID(label, arn)
	g.add(ontology.Node{ID: id, Label: label, Name: arn[strings.LastIndex(arn, "/")+1:],
		Properties: map[string]any{ontology.PropARN: arn}})
	return id
}

// clusterAdmin is the cluster's synthetic cluster-admin, the node the k8s collector draws
// for a dump sent with ?cluster=<name>.
func (g *graph) clusterAdmin(name string) string {
	id := ingestion.KubeID(ontology.LabelIAMRole, name, "perspectivegraph:cluster-admin")
	g.add(ontology.Node{ID: id, Label: ontology.LabelIAMRole, Name: "cluster-admin (effective, " + name + ")",
		Properties: map[string]any{ontology.PropCrownJewel: true, "admin": true, "k8s_synthetic": true, "k8s_cluster": name}})
	return id
}

func (g *graph) slice() []ontology.Node {
	out := make([]ontology.Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	return out
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
