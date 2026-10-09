// Package kubernetes is the Kubernetes agentless connector: the backend reads the cluster
// it runs in, on the connectors' schedule, instead of waiting for a cron job to dump it
// with kubectl and post the dump.
//
// It reads what that dump holds - ingresses, services, pods, service accounts, roles and
// cluster roles with their bindings, nodes, and EKS's aws-auth map - and assembles the
// List `kubectl get … -A -o json` writes, which the existing k8s collector parses
// verbatim. So the topology, the cluster-to-cloud edges and the escalation primitives are
// found by the code that already finds them in a posted dump; only the acquisition is new.
// Secrets are not read: the collector has no use for them, and the role the chart grants
// does not include them.
package kubernetes

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// transport acquires the cluster's objects.
type transport interface {
	// Mode is a short label for logs and connector status: "incluster" or "fixtures".
	Mode() string
	// Fetch returns the objects as a kubectl List, and whether every kind was read. A List
	// missing a kind describes the cluster only in part, so it must not retract what it
	// no longer shows: the graph would lose every service account because one list call
	// was refused.
	Fetch(ctx context.Context) (raw []byte, complete bool, err error)
}

// Connector is the Kubernetes agentless connector.
type Connector struct {
	t       transport
	cluster string
	account string
	col     *k8s.Collector
}

// New builds the connector over a transport. cluster names the cluster as the estate knows
// it - on EKS, its EKS name, which is how the AWS connector keys its Pod Identity
// associations and access entries - and account, when set, is the AWS account its nodes
// run in, so a pod's escape to its node meets the instance the AWS connector read.
func New(t transport, cluster, account string) *Connector {
	return &Connector{t: t, cluster: cluster, account: account, col: k8s.New()}
}

// Mode exposes the transport mode for logging.
func (c *Connector) Mode() string { return c.t.Mode() }

// Source identifies the connector.
func (*Connector) Source() string { return "kubernetes" }

// Scope is the snapshot scope a complete pull declares: the same one a dump posted with
// ?snapshot=cluster:<name> declares, so the two describe one cluster the same way.
func (c *Connector) Scope() string { return "cluster:" + c.cluster }

// Collect reads the cluster and parses it. What could be read is returned even when a
// kind could not - with the error, and without the snapshot, so it adds and refreshes but
// retracts nothing.
func (c *Connector) Collect(ctx context.Context) ([]ontology.Event, error) {
	raw, complete, err := c.t.Fetch(ctx)
	if len(raw) == 0 {
		return nil, err
	}
	evs, perr := c.col.Parse(bytes.NewReader(raw), ingestion.Options{Cluster: c.cluster, Account: c.account})
	if perr != nil {
		return nil, errors.Join(err, fmt.Errorf("parse: %w", perr))
	}
	if complete && err == nil {
		for i := range evs {
			evs[i].Snapshot = &ontology.Snapshot{Scope: c.Scope()}
		}
	}
	return evs, err
}
