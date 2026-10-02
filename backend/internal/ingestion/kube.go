package ingestion

import "github.com/luiacuaniello/perspectivegraph/pkg/ontology"

// KubeID is the node id of a Kubernetes object: its key inside the cluster, qualified by
// the cluster when one is named (?cluster=). With no cluster named it is exactly the id it
// always was, so an estate of one cluster keeps its nodes. Every source that names a
// Kubernetes object keys it here - the cluster dump, and Falco for the pod an alert came
// from - so they land on one node.
func KubeID(label ontology.Label, cluster, key string) string {
	if cluster == "" {
		return ontology.NewID(label, key)
	}
	return ontology.NewID(label, "cluster="+cluster, key)
}
