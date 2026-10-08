package terraform

// EKS access, in the shape the eks collector reads: per cluster, the IAM roles its pods
// get out as (Pod Identity associations) and the IAM principals that get in, with the
// access policies they hold (access entries). A cluster is named by its name, which is
// how the collector keys the cluster's Kubernetes objects.

type eksBundle struct {
	Clusters []eksCluster `json:"clusters"`
}

type eksCluster struct {
	Name                    string           `json:"name"`
	PodIdentityAssociations []eksPodIdentity `json:"podIdentityAssociations"`
	AccessEntries           []eksAccessEntry `json:"accessEntries"`
}

type eksPodIdentity struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	RoleArn        string `json:"roleArn"`
}

type eksAccessEntry struct {
	PrincipalArn   string            `json:"principalArn"`
	AccessPolicies []eksAccessPolicy `json:"accessPolicies"`
}

type eksAccessPolicy struct {
	PolicyArn   string `json:"policyArn"`
	AccessScope struct {
		Type string `json:"type"`
	} `json:"accessScope"`
}

func (p *Plan) eksAccess(v View) (eksBundle, []string) {
	var b eksBundle
	var notes []string
	clusters := map[string]*eksCluster{}
	var order []string
	cluster := func(name string) *eksCluster {
		if c, ok := clusters[name]; ok {
			return c
		}
		c := &eksCluster{Name: name, PodIdentityAssociations: []eksPodIdentity{}, AccessEntries: []eksAccessEntry{}}
		clusters[name] = c
		order = append(order, name)
		return c
	}
	entries := map[[2]string]int{} // (cluster, principal) -> position in the cluster's entries
	entry := func(c *eksCluster, principal string) *eksAccessEntry {
		k := [2]string{c.Name, principal}
		if i, ok := entries[k]; ok {
			return &c.AccessEntries[i]
		}
		entries[k] = len(c.AccessEntries)
		c.AccessEntries = append(c.AccessEntries, eksAccessEntry{PrincipalArn: principal, AccessPolicies: []eksAccessPolicy{}})
		return &c.AccessEntries[len(c.AccessEntries)-1]
	}
	for _, r := range p.Resources(v, "aws_eks_pod_identity_association") {
		if !r.Managed() {
			continue
		}
		name, role := p.Str(v, r, "cluster_name"), p.Str(v, r, "role_arn")
		if name == "" || role == "" {
			notes = append(notes, r.Address+": its cluster or role is known only after apply")
			continue
		}
		ns, _ := r.Values["namespace"].(string)
		sa, _ := r.Values["service_account"].(string)
		c := cluster(name)
		c.PodIdentityAssociations = append(c.PodIdentityAssociations, eksPodIdentity{Namespace: ns, ServiceAccount: sa, RoleArn: role})
	}
	for _, r := range p.Resources(v, "aws_eks_access_entry", "aws_eks_access_policy_association") {
		if !r.Managed() {
			continue
		}
		name, principal := p.Str(v, r, "cluster_name"), p.Str(v, r, "principal_arn")
		if name == "" || principal == "" {
			notes = append(notes, r.Address+": its cluster or principal is known only after apply")
			continue
		}
		e := entry(cluster(name), principal)
		if r.Type != "aws_eks_access_policy_association" {
			continue
		}
		pol := eksAccessPolicy{PolicyArn: p.Str(v, r, "policy_arn")}
		pol.AccessScope.Type = p.Str(v, r, "access_scope", 0, "type")
		e.AccessPolicies = append(e.AccessPolicies, pol)
	}
	for _, name := range order {
		b.Clusters = append(b.Clusters, *clusters[name])
	}
	return b, notes
}
