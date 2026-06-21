import { useEffect, useMemo, useState } from "react";
import { fetchDashboard, type AttackPath, type Dashboard } from "./api/client";
import PostureOverview from "./components/PostureOverview";
import AttackPathList from "./components/AttackPathList";
import GraphCanvas from "./components/GraphCanvas";

const POLL_MS = 5000;

export default function App() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AttackPath | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      fetchDashboard()
        .then((d) => {
          if (!alive) return;
          setData(d);
          setError(null);
        })
        .catch((e) => alive && setError(String(e.message ?? e)));
    load();
    const t = setInterval(load, POLL_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  // Keep the selected path in sync with refreshed data (or auto-pick the top one).
  useEffect(() => {
    if (!data) return;
    if (selected) {
      const still = data.attackPaths.find((p) => p.id === selected.id);
      setSelected(still ?? data.attackPaths[0] ?? null);
    } else {
      setSelected(data.attackPaths[0] ?? null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  const { highlightNodes, highlightEdges } = useMemo(() => {
    const n = new Set<string>();
    const e = new Set<string>();
    selected?.nodes.forEach((node) => n.add(node.id));
    selected?.steps.forEach((s) => e.add(`${s.from}->${s.to}`));
    return { highlightNodes: n, highlightEdges: e };
  }, [selected]);

  return (
    <div className="flex h-full flex-col p-5">
      <header className="mb-4 flex items-baseline justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-50">
            🛡️ AegisGraph <span className="text-sm font-normal text-slate-400">DevSecOps Context Engine</span>
          </h1>
          <p className="text-xs text-slate-500">
            Reachable attack paths across code, cloud & runtime — not another flat CVE list.
          </p>
        </div>
        {error && (
          <span className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-1 text-xs text-amber-300">
            backend unreachable: {error}
          </span>
        )}
      </header>

      {data && (
        <>
          <div className="mb-4">
            <PostureOverview posture={data.posture} />
          </div>

          {data.invariantViolations.length > 0 && (
            <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
              <span className="font-semibold text-amber-300">Policy invariants violated:</span>{" "}
              {data.invariantViolations.map((v) => (
                <span key={v.invariantId + v.nodes.map((n) => n.id).join()} className="mr-2 text-amber-200">
                  <code>{v.invariantId}</code> ({v.severity})
                </span>
              ))}
            </div>
          )}

          <div className="grid min-h-0 flex-1 grid-cols-12 gap-4">
            <aside className="col-span-4 flex min-h-0 flex-col gap-3 overflow-y-auto">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
                Attack paths ({data.attackPaths.length})
              </h2>
              <AttackPathList paths={data.attackPaths} selectedId={selected?.id ?? null} onSelect={setSelected} />
            </aside>

            <section className="col-span-8 min-h-0">
              <GraphCanvas
                nodes={data.graph.nodes}
                edges={data.graph.edges}
                highlightNodes={highlightNodes}
                highlightEdges={highlightEdges}
              />
            </section>
          </div>
        </>
      )}

      {!data && !error && <div className="flex-1 grid place-items-center text-slate-500">Loading…</div>}
    </div>
  );
}
