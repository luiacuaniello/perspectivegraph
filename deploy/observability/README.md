# Observability

Ready-to-use monitoring for a PerspectiveGraph deployment:

- `grafana-dashboard.json` - a Grafana dashboard for the `perspectivegraph_*` metrics
  (analyzer pass time, graph size, critical paths, ingest and connector rates, HTTP codes,
  dead-lettering, TTL pruning).
- `prometheus-alerts.yaml` - alerting rules for the SLOs in
  [../../docs/OPERATIONS.md](../../docs/OPERATIONS.md#6-observability--slos).

## Scrape the metrics

The backend exposes Prometheus metrics at `GET /metrics` on the API port (8080). A minimal
scrape config:

```yaml
scrape_configs:
  - job_name: perspectivegraph
    metrics_path: /metrics
    static_configs:
      - targets: ["perspectivegraph-backend:8080"]
```

On Kubernetes, point a `ServiceMonitor`/`PodMonitor` (Prometheus Operator) at the backend
service instead.

## Load the alert rules

- Plain Prometheus: reference the file from `rule_files:` in `prometheus.yml`.
- Prometheus Operator: wrap the `groups:` in a `PrometheusRule` custom resource.

## Import the dashboard

Grafana → Dashboards → New → Import → upload `grafana-dashboard.json`, then pick your
Prometheus data source when prompted (the dashboard uses a `datasource` variable, so it is
not tied to a specific data-source UID).

## What to watch

The dashboard and alerts track the four signals that matter operationally: the **analyzer**
keeping the attack-path view current (pass rate + p95 latency), **ingestion** health
(rates, normalize errors, dead-lettering), **connector** health (runs by result), and the
**API** (request rate by code, 401/403 and 5xx). For load/scale characterization of the
analyzer, see [../../docs/SCALE.md](../../docs/SCALE.md).
