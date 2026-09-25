// Package metrics is the Prometheus instrumentation surface. A security platform
// you can't observe is one you operate blind - so ingest throughput, the
// normalization outcome, broker dead-letters, and analyzer pass timing are all
// exported here and scraped at /metrics. Collectors are package-level so any
// layer can record without plumbing a handle through every constructor.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// reg is a private registry: we control exactly what is exposed (no global
	// default-registry surprises) and still ship Go runtime + process metrics.
	reg = prometheus.NewRegistry()

	IngestEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_ingest_events_total",
		Help: "Events accepted at the ingest webhook, by source collector.",
	}, []string{"source"})

	IngestNodes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "perspectivegraph_ingest_nodes_total",
		Help: "Nodes carried by accepted ingest events.",
	})

	IngestEdges = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "perspectivegraph_ingest_edges_total",
		Help: "Edges carried by accepted ingest events.",
	})

	// NormalizeEvents counts every delivery the consumer handles: one "error" per failed
	// attempt, so a redelivered event that then succeeds counts both. It was registered
	// and never incremented, which left the PerspectiveGraphIngestErrors alert built on it
	// unable to fire.
	NormalizeEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_normalize_events_total",
		Help: "Events processed by the normalizer, by result (ok|error).",
	}, []string{"result"})

	BrokerDeadLettered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "perspectivegraph_broker_dead_lettered_total",
		Help: "Events terminated after exhausting redeliveries (sent to the DLQ).",
	})

	// BrokerConnected is 1 while the NATS connection is up. It goes to 0 during a
	// reconnect, when events are still accepted by nobody: ingest returns 502 and the
	// consumer waits. Alert on it staying 0, not on a single dip.
	BrokerConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "perspectivegraph_broker_connected",
		Help: "1 while the connection to the NATS event bus is up, 0 while it is reconnecting or closed.",
	})

	AnalyzerPasses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "perspectivegraph_analyzer_passes_total",
		Help: "Completed analyzer passes (all tenants).",
	})

	AnalyzerPassSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "perspectivegraph_analyzer_pass_seconds",
		Help:    "Duration of a single tenant's analyzer pass.",
		Buckets: prometheus.DefBuckets,
	})

	AnalyzerCriticalPaths = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "perspectivegraph_analyzer_critical_paths",
		Help: "Critical attack paths found in the latest pass, by tenant.",
	}, []string{"tenant"})

	// Scale visibility: the graph the analyzer reasons over, and how long the
	// (parallel) per-seed pathfinding itself takes - so an operator can see growth
	// and pass latency before either becomes a problem.
	AnalyzerGraphNodes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "perspectivegraph_analyzer_graph_nodes",
		Help: "Nodes in the snapshot the analyzer last reasoned over, by tenant.",
	}, []string{"tenant"})

	AnalyzerGraphEdges = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "perspectivegraph_analyzer_graph_edges",
		Help: "Edges in the snapshot the analyzer last reasoned over, by tenant.",
	}, []string{"tenant"})

	AnalyzerPathfindSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "perspectivegraph_analyzer_pathfind_seconds",
		Help:    "Duration of just the critical-path search within a pass (parallel per-seed Dijkstra).",
		Buckets: prometheus.DefBuckets,
	})

	// Snapshot acquisition cost and mode: a full re-read of the graph vs an
	// incremental delta patched onto the in-process cache (the scale win on a
	// large, slowly-changing graph).
	AnalyzerSnapshotSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "perspectivegraph_analyzer_snapshot_seconds",
		Help:    "Duration of acquiring the graph snapshot for a pass (full read or delta patch).",
		Buckets: prometheus.DefBuckets,
	})

	AnalyzerSnapshots = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_analyzer_snapshots_total",
		Help: "Snapshot acquisitions by mode (full|delta).",
	}, []string{"mode"})

	// GraphPendingEdges is how many edges wait for an endpoint no event has brought yet.
	// A few that come and go are feeds arriving out of order; a number that only grows
	// is a feed naming assets nothing else describes, which never become routes.
	GraphPendingEdges = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "perspectivegraph_graph_pending_edges",
		Help: "Edges parked until their missing endpoint arrives (dropped after 7 days), by tenant.",
	}, []string{"tenant"})

	GraphPrunedNodes = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "perspectivegraph_graph_pruned_nodes_total",
		Help: "Stale nodes removed by the TTL pruner (assets that left the source feeds).",
	})

	GraphPrunedEdges = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "perspectivegraph_graph_pruned_edges_total",
		Help: "Stale edges removed by the TTL pruner.",
	})

	AuditPrunedRecords = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "perspectivegraph_audit_pruned_records_total",
		Help: "Audit records removed by retention (AUDIT_RETENTION), oldest first.",
	})

	// AuthDenied counts refused credentials where the refusal is decided, by surface
	// (api|ingest) and a short reason. The HTTP counter below records only status
	// classes, so an alert on 401/403 there could never match; and ingest requests were
	// not counted at all.
	AuthDenied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_auth_denied_total",
		Help: "Requests refused for their credential, by surface (api|ingest) and reason.",
	}, []string{"surface", "reason"})

	// IngestSignatures counts accepted ingest signatures by version. v1 covers the body
	// only; when it stays at zero, every sender signs v2 and INGEST_HMAC_ACCEPT_V1 can be
	// turned off.
	IngestSignatures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_ingest_signatures_total",
		Help: "Accepted ingest HMAC signatures, by version (v1|v2).",
	}, []string{"version"})

	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_http_requests_total",
		Help: "HTTP requests served, by handler and status class.",
	}, []string{"handler", "code"})

	// APIHeavyRefused counts heavy analyses (what-ifs, fix verifications, custom risk
	// simulations, k-shortest searches) the API refused: "budget" when one request asked
	// for more than its share, "busy" when no slot freed up in time. A steady "busy" rate
	// means real demand is outgrowing the cores; bursts of "budget" mean someone is
	// asking for everything at once.
	APIHeavyRefused = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_api_heavy_refused_total",
		Help: "Heavy GraphQL analyses refused, by reason (budget|busy).",
	}, []string{"reason"})

	ConnectorRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_connector_runs_total",
		Help: "Agentless connector collection runs, by source and result (ok|error).",
	}, []string{"source", "result"})

	ConnectorEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "perspectivegraph_connector_events_total",
		Help: "Events emitted by agentless connectors, by source.",
	}, []string{"source"})
)

func init() {
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		IngestEvents, IngestNodes, IngestEdges,
		NormalizeEvents, BrokerDeadLettered, BrokerConnected,
		AnalyzerPasses, AnalyzerPassSeconds, AnalyzerCriticalPaths,
		AnalyzerGraphNodes, AnalyzerGraphEdges, AnalyzerPathfindSeconds,
		AnalyzerSnapshotSeconds, AnalyzerSnapshots,
		GraphPrunedNodes, GraphPrunedEdges, GraphPendingEdges, AuditPrunedRecords,
		HTTPRequests, APIHeavyRefused, AuthDenied, IngestSignatures,
		ConnectorRuns, ConnectorEvents,
	)
	// Both results exist from the first scrape, so a panel or a ratio reads 0 rather than
	// "no data" on an instance that has not failed yet.
	NormalizeEvents.WithLabelValues("ok")
	NormalizeEvents.WithLabelValues("error")
}

// Handler serves the Prometheus exposition format for our registry.
func Handler() http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// Count records an HTTP request outcome for a named handler.
func Count(handler string, code int) {
	HTTPRequests.WithLabelValues(handler, codeClass(code)).Inc()
}

func codeClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}
