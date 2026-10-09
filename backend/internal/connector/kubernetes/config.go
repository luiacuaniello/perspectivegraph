package kubernetes

import (
	"errors"
	"fmt"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Config selects and configures the connector's transport.
type Config struct {
	// Mode is "incluster" (default: the cluster the backend runs in, read with its service
	// account's token) or "fixtures" (a dump on disk, for the demo and tests).
	Mode string
	// Cluster names the cluster (K8S_CLUSTER_NAME). Required: Kubernetes names repeat
	// across clusters, and a cluster cannot tell its own name.
	Cluster string
	// Account is the AWS account the nodes run in, on EKS (K8S_AWS_ACCOUNT). Optional.
	Account string
	// FixturesDir holds k8s-sample.json for fixtures mode.
	FixturesDir string
}

// NewFromConfig builds the connector with the transport cfg.Mode selects.
func NewFromConfig(cfg Config) (*Connector, error) {
	if cfg.Cluster == "" {
		return nil, errors.New("K8S_CLUSTER_NAME is required: Kubernetes names repeat across clusters, and on EKS the name is how the cluster's objects meet the AWS account's - use the EKS cluster name")
	}
	if !ontology.ValidScope("cluster:" + cfg.Cluster) {
		return nil, fmt.Errorf("K8S_CLUSTER_NAME %q: want printable characters without spaces, at most %d", cfg.Cluster, ontology.MaxScopeLen-len("cluster:"))
	}
	switch cfg.Mode {
	case "", "incluster":
		t, err := InCluster()
		if err != nil {
			return nil, err
		}
		return New(t, cfg.Cluster, cfg.Account), nil
	case "fixtures":
		return New(Fixtures(cfg.FixturesDir), cfg.Cluster, cfg.Account), nil
	default:
		return nil, fmt.Errorf("unknown kubernetes connector mode %q (want incluster or fixtures)", cfg.Mode)
	}
}
