import { useEffect, useMemo, useState } from "react";
import { exportUrl, fetchDashboard, fetchHistory, fetchStatus, type Dashboard, type History } from "./api/client";
import Sidebar, { type View } from "./components/Sidebar";
import PostureOverview from "./components/PostureOverview";
import AttackPathList from "./components/AttackPathList";
import AttackPathDetail from "./components/AttackPathDetail";
import RemediationPlan from "./components/RemediationPlan";
import ViolationList from "./components/ViolationList";
import GraphCanvas from "./components/GraphCanvas";
import SearchView from "./components/SearchView";
import AssistantView from "./components/AssistantView";
import IntroBanner, { useIntroDismissed } from "./components/IntroBanner";
import EmptyState from "./components/EmptyState";
import Legend from "./components/Legend";
import Button from "./components/ui/Button";
import DashboardSkeleton from "./components/DashboardSkeleton";
import ThemeToggle from "./components/ThemeToggle";
import { InfoIcon } from "./components/icons";
import { hasRuntimeToken, clearAuthToken } from "./api/client";

const POLL_MS = 5000;

const VIEWS: View[] = ["overview", "paths", "plan", "graph", "violations", "search", "assistant"];

// Deep-linkable views: #paths, #graph, … open the app on that section.
function viewFromHash(): View {
  const h = window.location.hash.slice(1) as View;
  return VIEWS.includes(h) ? h : "overview";
}

const VIEW_META: Record<View, { title: string; subtitle: string }> = {
  overview: {
    title: "Security posture",
    subtitle: "Reachable attack paths across code, cloud & runtime - not another flat CVE list.",
  },
  paths: {
    title: "Attack paths",
    subtitle: "Ranked end-to-end routes from internet exposure to crown jewels.",
  },
  plan: {
    title: "Remediation plan",
    subtitle: "The fewest fixes that eliminate the most critical-path risk - choke points first.",
  },
  graph: {
    title: "Environment graph",
    subtitle: "Every asset, identity and finding as one connected map.",
  },
  violations: {
    title: "Policy violations",
    subtitle: "Architectural invariants the current environment breaks.",
  },
  search: {
    title: "Search",
    subtitle: "Full-text search across every indexed asset and finding (OpenSearch).",
  },
  assistant: {
    title: "AI assistant",
    subtitle: "Ask about your attack surface and brief the board - grounded in the live graph (Claude).",
  },
};

export default function App() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setViewState] = useState<View>(viewFromHash);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  // "" = whole environment; otherwise scope paths + graph to one application.
  const [app, setApp] = useState<string>("");
  const [analyzedAt, setAnalyzedAt] = useState<string | null>(null);
  const [pruned, setPruned] = useState<{ nodes: number; edges: number } | null>(null);
  const [history, setHistory] = useState<History | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  // Triage: hide suppressed paths by default; bump reloadKey to refetch after a
  // suppress / un-suppress so the board reflects the decision immediately.
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const reload = () => setReloadKey((k) => k + 1);
  const intro = useIntroDismissed();

  const setView = (v: View) => {
    setViewState(v);
    window.location.hash = v;
  };

  useEffect(() => {
    let alive = true;
    let lastFp = "";

    const refreshFull = () =>
      fetchDashboard(app || undefined)
        .then((d) => {
          if (!alive) return;
          setData(d);
          setError(null);
        })
        .catch((e) => alive && setError(String(e.message ?? e)));

    // The temporal view is light and evolves on a steady graph, so poll it on its
    // own cadence rather than only on the (heavy) dashboard refetch.
    const refreshHistory = () =>
      fetchHistory()
        .then((h) => alive && setHistory(h))
        .catch(() => {});

    // Poll the cheap fingerprint; only re-pull the full dashboard when it moves.
    const poll = () =>
      fetchStatus()
        .then((s) => {
          if (!alive) return;
          if (s.analyzedAt) setAnalyzedAt(s.analyzedAt);
          setPruned({ nodes: s.prunedNodes ?? 0, edges: s.prunedEdges ?? 0 });
          const fp = `${s.version}:${s.passes}`;
          if (fp !== lastFp) {
            lastFp = fp;
            return refreshFull();
          }
        })
        .catch((e) => alive && setError(String(e.message ?? e)));

    // Initial: one full load, then prime the fingerprint so polls stay cheap.
    refreshFull().then(() =>
      fetchStatus()
        .then((s) => {
          lastFp = `${s.version}:${s.passes}`;
          if (!alive) return;
          if (s.analyzedAt) setAnalyzedAt(s.analyzedAt);
          setPruned({ nodes: s.prunedNodes ?? 0, edges: s.prunedEdges ?? 0 });
        })
        .catch(() => {}),
    );
    refreshHistory();
    const t = setInterval(() => {
      poll();
      refreshHistory();
    }, POLL_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [app, reloadKey]);

  // Derive the selected path from the freshest data (fall back to the top one).
  const selected = useMemo(() => {
    const paths = data?.attackPaths ?? [];
    return paths.find((p) => p.id === selectedPathId) ?? paths[0] ?? null;
  }, [data, selectedPathId]);

  // The list hides triaged-off (suppressed) paths unless the analyst opts in.
  const allPaths = useMemo(() => data?.attackPaths ?? [], [data]);
  const visiblePaths = useMemo(
    () => (showSuppressed ? allPaths : allPaths.filter((p) => !p.suppressed)),
    [allPaths, showSuppressed],
  );
  const suppressedCount = useMemo(() => allPaths.filter((p) => p.suppressed).length, [allPaths]);

  const { highlightNodes, highlightEdges } = useMemo(() => {
    const n = new Set<string>();
    const e = new Set<string>();
    selected?.nodes.forEach((node) => n.add(node.id));
    selected?.steps.forEach((s) => e.add(`${s.from}->${s.to}`));
    return { highlightNodes: n, highlightEdges: e };
  }, [selected]);

  const openPath = (id: string) => {
    setSelectedPathId(id);
    setView("paths");
  };

  const meta = VIEW_META[view];

  return (
    <div className="flex h-full">
      <Sidebar
        view={view}
        onNavigate={setView}
        pathCount={data?.attackPaths.length ?? 0}
        violationCount={data?.posture.policyViolations ?? 0}
        live={!error}
        analyzedAt={analyzedAt}
        pruned={pruned}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        aiEnabled={data?.aiEnabled ?? false}
      />
      {/* Mobile drawer backdrop */}
      {sidebarOpen && (
        <div
          onClick={() => setSidebarOpen(false)}
          className="fixed inset-0 z-30 bg-black/40 lg:hidden"
          aria-hidden="true"
        />
      )}

      <main className="flex min-w-0 flex-1 flex-col">
        <header className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2 px-4 pb-4 pt-6 sm:px-8">
          <div className="flex items-center gap-2.5">
            <button
              onClick={() => setSidebarOpen(true)}
              aria-label="Open menu"
              className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-edge bg-panel text-slate-500 shadow-card transition hover:text-accent lg:hidden"
            >
              <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round">
                <path d="M3 6h14M3 10h14M3 14h14" />
              </svg>
            </button>
            <div>
              <h1 className="text-xl font-semibold tracking-tight text-slate-900">{meta.title}</h1>
              <p className="mt-0.5 text-[13px] text-slate-500">{meta.subtitle}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <ThemeToggle />
            {hasRuntimeToken() && (
              <Button
                variant="secondary"
                size="md"
                onClick={() => {
                  clearAuthToken();
                  window.location.reload();
                }}
              >
                Sign out
              </Button>
            )}
            {view === "overview" && intro.dismissed && (
              <Button variant="secondary" size="md" onClick={intro.reopen} icon={<InfoIcon className="h-4 w-4" />}>
                How to read this
              </Button>
            )}
            {error && (
              <span className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-700">
                backend unreachable: {error}
              </span>
            )}
            {data && data.posture.nodes > 0 && (
              <div className="flex items-center gap-1.5">
                <Button
                  variant="secondary"
                  size="md"
                  href={exportUrl("oscal")}
                  download="perspectivegraph-oscal.json"
                  title="Download the posture as a NIST OSCAL assessment-results document (for GRC/auditors)"
                >
                  ↓ OSCAL
                </Button>
                <Button
                  variant="secondary"
                  size="md"
                  href={exportUrl("ndjson")}
                  download="perspectivegraph-enrichment.ndjson"
                  title="Download per-asset risk enrichment as NDJSON (for Splunk/Elastic/Sentinel)"
                >
                  ↓ SIEM
                </Button>
              </div>
            )}
            {data && data.applications.length > 0 && (
              <label className="flex items-center gap-2 text-xs text-muted">
                Application
                <select
                  value={app}
                  onChange={(e) => {
                    setApp(e.target.value);
                    setSelectedPathId(null);
                  }}
                  className="rounded-lg border border-edge bg-panel shadow-card px-2.5 py-1.5 text-xs text-slate-700 outline-none focus:border-accent"
                >
                  <option value="">All applications</option>
                  {data.applications.map((a) => (
                    <option key={a} value={a}>
                      {a}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        </header>

        {!data && !error && (
          <div className="min-h-0 flex-1 px-4 pb-6 sm:px-8">
            <DashboardSkeleton />
          </div>
        )}

        {data && data.posture.nodes === 0 && (
          <div className="min-h-0 flex-1 px-4 pb-6 sm:px-8">
            <EmptyState />
          </div>
        )}

        {data && data.posture.nodes > 0 && (
          <div className="min-h-0 flex-1 px-4 pb-6 sm:px-8">
            {view === "overview" && (
              <div className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto pr-1">
                {!intro.dismissed && <IntroBanner onDismiss={intro.dismiss} />}
                <PostureOverview posture={data.posture} risk={data.riskSimulation} history={history ?? undefined} validation={data.validation} />

                {data.invariantViolations.length > 0 && (
                  <button
                    onClick={() => setView("violations")}
                    className="flex items-center justify-between rounded-xl border border-amber-500/30 bg-amber-500/[0.07] px-4 py-3 text-left transition hover:border-amber-500/60"
                  >
                    <span className="text-sm text-amber-700">
                      <span className="font-semibold">{data.invariantViolations.length} policy invariant
                      {data.invariantViolations.length === 1 ? "" : "s"} violated</span>
                      <span className="text-amber-700/70">
                        {" "}
                        - {[...new Set(data.invariantViolations.map((v) => v.invariantId))].join(", ")}
                      </span>
                    </span>
                    <span className="text-xs text-amber-700/80">review →</span>
                  </button>
                )}

                {data.remediationPlan.length > 0 && (
                  <button
                    onClick={() => setView("plan")}
                    className="flex items-center justify-between rounded-xl border border-accent/30 bg-accent/[0.06] px-4 py-3 text-left transition hover:border-accent/60"
                  >
                    <span className="text-sm text-slate-700">
                      <span className="font-semibold text-accent">
                        {data.remediationPlan.length} fix
                        {data.remediationPlan.length === 1 ? "" : "es"}
                      </span>{" "}
                      eliminate{" "}
                      <span className="font-semibold">
                        {(
                          data.remediationPlan.reduce((a, f) => a + f.coveragePct, 0) * 100
                        ).toFixed(0)}
                        %
                      </span>{" "}
                      of critical-path risk
                    </span>
                    <span className="text-xs text-slate-500">see plan →</span>
                  </button>
                )}

                <section>
                  <div className="mb-2 flex items-baseline justify-between">
                    <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">
                      Top attack paths
                    </h2>
                    <button
                      onClick={() => setView("paths")}
                      className="text-xs text-slate-500 transition hover:text-slate-600"
                    >
                      view all ({data.attackPaths.length}) →
                    </button>
                  </div>
                  <AttackPathList
                    paths={data.attackPaths.slice(0, 3)}
                    selectedId={null}
                    onSelect={(p) => openPath(p.id)}
                  />
                </section>

                <Legend />
              </div>
            )}

            {view === "paths" && (
              // Mobile: one scrolling column (list above detail). Desktop: a 4/8
              // split where each panel scrolls on its own.
              <div className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto lg:grid lg:grid-cols-12 lg:gap-5 lg:overflow-hidden">
                <div className="min-h-0 lg:col-span-4 lg:overflow-y-auto lg:pr-1">
                  {suppressedCount > 0 && (
                    <label className="mb-2 flex items-center gap-2 text-[11px] text-slate-500">
                      <input
                        type="checkbox"
                        checked={showSuppressed}
                        onChange={(e) => setShowSuppressed(e.target.checked)}
                        className="accent-slate-600"
                      />
                      Show suppressed ({suppressedCount})
                    </label>
                  )}
                  <AttackPathList
                    paths={visiblePaths}
                    selectedId={selected?.id ?? null}
                    onSelect={(p) => setSelectedPathId(p.id)}
                  />
                </div>
                <div className="min-h-0 lg:col-span-8 lg:overflow-y-auto lg:pr-1">
                  {selected ? (
                    <AttackPathDetail
                      path={selected}
                      onShowInGraph={() => setView("graph")}
                      onTriaged={reload}
                      aiEnabled={data.aiEnabled}
                    />
                  ) : (
                    <div className="rounded-xl border border-edge bg-panel shadow-card p-6 text-sm text-slate-500">
                      No attack paths yet. Seed the demo with{" "}
                      <code className="text-teal-700">make seed</code>.
                    </div>
                  )}
                </div>
              </div>
            )}

            {view === "graph" && (
              <div className="flex h-full min-h-0 flex-col gap-3">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <label className="text-xs font-medium text-muted" htmlFor="path-select">
                    Highlight path
                  </label>
                  <select
                    id="path-select"
                    value={selected?.id ?? ""}
                    onChange={(e) => setSelectedPathId(e.target.value || null)}
                    className="w-full max-w-md rounded-lg border border-edge bg-panel shadow-card px-3 py-1.5 text-xs text-slate-700 outline-none focus:border-accent focus:ring-2 focus:ring-accent/15 sm:w-auto"
                  >
                    {data.attackPaths.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.nodes[0]?.name} → {p.nodes[p.nodes.length - 1]?.name} (
                        {(p.score * 100).toFixed(0)}%{p.runtimeConfirmed ? " · runtime" : ""})
                      </option>
                    ))}
                  </select>
                  <span className="text-[11px] text-slate-400">
                    The graph centers on the selected route · use the controls (top-right) to zoom &amp; fit.
                  </span>
                </div>
                <div className="min-h-0 flex-1">
                  <GraphCanvas
                    nodes={data.graph.nodes}
                    edges={data.graph.edges}
                    highlightNodes={highlightNodes}
                    highlightEdges={highlightEdges}
                  />
                </div>
              </div>
            )}

            {view === "plan" && (
              <div className="h-full min-h-0 overflow-y-auto pr-1">
                <RemediationPlan plan={data.remediationPlan} pathCount={data.attackPaths.length} />
              </div>
            )}

            {view === "violations" && (
              <div className="h-full min-h-0 overflow-y-auto pr-1">
                <ViolationList violations={data.invariantViolations} />
              </div>
            )}

            {view === "search" && <SearchView enabled={data.searchEnabled} />}
            {view === "assistant" && <AssistantView />}
          </div>
        )}
      </main>
    </div>
  );
}
