import type { AttackPath } from "../api/client";

interface Props {
  paths: AttackPath[];
  selectedId: string | null;
  onSelect: (p: AttackPath) => void;
}

function scoreColor(score: number): string {
  if (score >= 0.3) return "bg-rose-500/20 text-rose-300 border-rose-500/40";
  if (score >= 0.1) return "bg-amber-500/20 text-amber-300 border-amber-500/40";
  return "bg-slate-500/20 text-slate-300 border-slate-500/40";
}

export default function AttackPathList({ paths, selectedId, onSelect }: Props) {
  if (paths.length === 0) {
    return (
      <div className="rounded-lg border border-edge bg-panel p-4 text-sm text-slate-400">
        No critical attack paths. Seed the demo with <code className="text-teal-300">make seed</code> to
        see one light up.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {paths.map((p) => {
        const selected = p.id === selectedId;
        return (
          <button
            key={p.id}
            onClick={() => onSelect(p)}
            className={`rounded-lg border p-3 text-left transition ${
              selected ? "border-rose-500 bg-rose-500/10" : "border-edge bg-panel hover:border-slate-500"
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium text-slate-100">
                {p.runtimeConfirmed && <span title="Runtime-confirmed by Falco">⚡ </span>}
                {p.nodes[0]?.name} → {p.nodes[p.nodes.length - 1]?.name}
              </span>
              <span className={`shrink-0 rounded border px-2 py-0.5 text-xs font-semibold ${scoreColor(p.score)}`}>
                {(p.score * 100).toFixed(0)}%
              </span>
            </div>
            <div className="mt-1 text-xs text-slate-400">
              {p.steps.length} hops · {p.nodes.map((n) => n.label).join(" → ")}
            </div>
          </button>
        );
      })}
    </div>
  );
}
