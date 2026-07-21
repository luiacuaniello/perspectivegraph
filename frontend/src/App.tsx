import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { exportUrl, fetchDashboard, fetchGraph, fetchHistory, fetchStatus, type Dashboard, type GraphData, type History } from "./api/client";
import Sidebar, { type View } from "./components/Sidebar";
import AttackPathList from "./components/AttackPathList";
import TodayView from "./components/TodayView";
import TrustView from "./components/TrustView";
import AttackPathDetail from "./components/AttackPathDetail";
// Code-split: GraphCanvas pulls in Cytoscape (the heaviest dependency), so it loads
// lazily only when the Graph view is opened - keeping the initial bundle small.
const GraphCanvas = lazy(() => import("./components/GraphCanvas"));
import SearchView from "./components/SearchView";
import AssistantView from "./components/AssistantView";
import IntroBanner, { useIntroDismissed } from "./components/IntroBanner";
import EmptyState from "./components/EmptyState";
import Button from "./components/ui/Button";
import DashboardSkeleton from "./components/DashboardSkeleton";
import ThemeToggle from "./components/ThemeToggle";
import { InfoIcon } from "./components/icons";
import { hasRuntimeToken, signOut } from "./api/client";

const POLL_MS = 5000;

const VIEWS: View[] = ["today", "paths", "trust", "assistant"];

// Deep-linkable views: #paths, #trust, … open the app on that section. The old
// hashes still resolve so existing links and bookmarks don't break.
const LEGACY_VIEWS: Record<string, View> = {
  overview: "today",
  plan: "today",
  violations: "today",
  graph: "paths",
  search: "paths",
};

function viewFromHash(): View {
  const h = window.location.hash.slice(1);
  if (VIEWS.includes(h as View)) return h as View;
  return LEGACY_VIEWS[h] ?? "today";
}

const VIEW_META: Record<View, { title: string; subtitle: string }> = {
  today: {
    title: "Today",
    subtitle: "What is exploitable right now, and the fewest changes that fix it.",
  },
  paths: {
    title: "Attack paths",
    subtitle: "Ranked end-to-end routes from internet exposure to sensitive assets.",
  },
  trust: {
    title: "Trust",
    subtitle: "How well the engine's probabilities match what actually happened.",
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
  // Search is a palette, not a page; the graph is a lens on the selected path,
  // not a destination you navigate away to.
  const [searchOpen, setSearchOpen] = useState(false);
  const [graphOpen, setGraphOpen] = useState(false);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
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

  // Command palette shortcuts. Search moved off the nav and onto the keyboard, so
  // it has to answer to the chord people already try (⌘K / Ctrl-K) and close on
  // escape like every other palette they use.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearchOpen((v) => !v);
      } else if (e.key === "Escape") {
        setSearchOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

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

  // The graph is a lens on the selected route, so it renders that route's
  // NEIGHBOURHOOD - its nodes plus everything one hop away - rather than the whole
  // environment. Handing Cytoscape a real estate (thousands of nodes) does not
  // produce a picture: the layout collapses into an unreadable smear and the tab
  // stalls. One hop keeps the answer legible and bounded no matter how big the
  // estate grows, which is the point of showing it beside a path at all.
  const pathNeighbourhood = useMemo(() => {
    if (!graphData || !selected) return { nodes: [], edges: [] };
    const core = new Set(selected.nodes.map((n) => n.id));
    const keep = new Set(core);
    for (const e of graphData.edges) {
      if (core.has(e.from)) keep.add(e.to);
      if (core.has(e.to)) keep.add(e.from);
    }
    return {
      nodes: graphData.nodes.filter((n) => keep.has(n.id)),
      edges: graphData.edges.filter((e) => keep.has(e.from) && keep.has(e.to)),
    };
  }, [graphData, selected]);

  // The environment graph is fetched only when someone opens it on a route, and
  // kept afterwards so toggling back is instant. Pulling it on every dashboard
  // poll is what made a real estate (thousands of nodes) time the request out.
  useEffect(() => {
    if (!graphOpen || graphData || graphLoading) return;
    setGraphLoading(true);
    fetchGraph(app || undefined)
      .then(setGraphData)
      .catch((e) => setError(String(e.message ?? e)))
      .finally(() => setGraphLoading(false));
  }, [graphOpen, graphData, graphLoading, app]);

  // A different application scope is a different graph.
  useEffect(() => {
    setGraphData(null);
  }, [app]);

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
        pathCount={data?.posture.activePaths ?? 0}
        onOpenSearch={data?.searchEnabled ? () => setSearchOpen(true) : undefined}
        live={!error}
        analyzedAt={analyzedAt}
        pruned={pruned}
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        aiEnabled={data?.aiEnabled ?? false}
        showPlayground={!hasRuntimeToken()}
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
        <header className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2 border-b border-edge/70 px-4 pb-4 pt-6 sm:px-8">
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
              <h1 className="text-[22px] font-bold leading-tight tracking-tight text-slate-900">{meta.title}</h1>
              <p className="mt-0.5 text-[13px] text-muted">{meta.subtitle}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <ThemeToggle />
            {hasRuntimeToken() && (
              <Button
                variant="secondary"
                size="md"
                onClick={() => {
                  void signOut();
                }}
              >
                Sign out
              </Button>
            )}
            {view === "today" && intro.dismissed && (
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
                  className="rounded-lg border border-edge bg-panel shadow-card px-2.5 py-1.5 text-xs text-slate-700 outline-hidden focus:border-accent"
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
            {view === "today" && (
              <div className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto pr-1">
                {!intro.dismissed && <IntroBanner onDismiss={intro.dismiss} />}
                <TodayView
                  posture={data.posture}
                  risk={data.riskSimulation}
                  paths={data.attackPaths}
                  plan={data.remediationPlan}
                  violations={data.invariantViolations}
                  calibration={data.calibration}
                  history={history ?? undefined}
                  onOpenPath={openPath}
                  onSeeAllPaths={() => setView("paths")}
                  onOpenTrust={() => setView("trust")}
                />
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
                  {selected && graphOpen ? (
                    // The graph earns its weight only as a lens on a route you have
                    // already chosen - never as a hairball you land on.
                    <div className="flex h-full min-h-0 flex-col gap-2">
                      <div className="flex items-center justify-between">
                        <span className="truncate text-[12px] text-muted">
                          {selected.nodes[0]?.name} → {selected.nodes[selected.nodes.length - 1]?.name} in context
                          {pathNeighbourhood.nodes.length > 0 && (
                            <span className="text-slate-500">
                              {" "}· {pathNeighbourhood.nodes.length} of {graphData?.nodes.length ?? 0} assets, one hop out
                            </span>
                          )}
                        </span>
                        <Button variant="secondary" size="sm" onClick={() => setGraphOpen(false)}>
                          Back to detail
                        </Button>
                      </div>
                      <div className="min-h-[24rem] flex-1">
                        <Suspense fallback={<div className="grid h-full place-items-center text-xs text-muted">Loading graph…</div>}>
                          {graphLoading && !graphData && (
                            <div className="grid h-full place-items-center text-xs text-muted">Loading the environment graph…</div>
                          )}
                          <GraphCanvas
                            nodes={pathNeighbourhood.nodes}
                            edges={pathNeighbourhood.edges}
                            highlightNodes={highlightNodes}
                            highlightEdges={highlightEdges}
                          />
                        </Suspense>
                      </div>
                    </div>
                  ) : selected ? (
                    <AttackPathDetail
                      path={selected}
                      onShowInGraph={() => setGraphOpen(true)}
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

            {view === "trust" && (
              <div className="h-full min-h-0 overflow-y-auto pr-1">
                <TrustView
                  calibration={data.calibration}
                  trend={data.calibrationTrend}
                  validation={data.validation}
                  risk={data.riskSimulation}
                />
              </div>
            )}

            {view === "assistant" && <AssistantView />}
          </div>
        )}
      </main>

      {searchOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 px-4 pt-[12vh]"
          onClick={() => setSearchOpen(false)}
        >
          <div
            className="w-full max-w-2xl rounded-2xl border border-edge bg-panel p-4 shadow-lift"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-3 flex items-center justify-between">
              <span className="text-[12px] text-muted">Search assets and findings</span>
              <kbd className="rounded border border-edge px-1.5 py-0.5 text-[10px] text-slate-400">esc</kbd>
            </div>
            <SearchView enabled={data?.searchEnabled ?? false} />
          </div>
        </div>
      )}
    </div>
  );
}
