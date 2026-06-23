import type { AttackPath } from "../api/client";
import { ZapIcon } from "./icons";

interface Props {
  paths: AttackPath[];
  selectedId: string | null;
  onSelect: (p: AttackPath) => void;
}

function scoreTone(score: number): string {
  if (score >= 0.3) return "bg-red-500/15 text-red-700";
  if (score >= 0.1) return "bg-amber-500/15 text-amber-700";
  return "bg-slate-500/15 text-slate-600";
}

function priorityTone(label?: string | null): string {
  if (label === "P1") return "bg-red-600 text-white";
  if (label === "P2") return "bg-amber-500/20 text-amber-700";
  return "bg-slate-500/15 text-slate-600";
}

export default function AttackPathList({ paths, selectedId, onSelect }: Props) {
  if (paths.length === 0) {
    return (
      <div className="rounded-xl border border-edge bg-panel shadow-card p-4 text-sm text-slate-500">
        No critical attack paths. Seed the demo with <code className="text-teal-700">make seed</code> to
        see one light up.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {paths.map((p, rank) => {
        const selected = p.id === selectedId;
        const entry = p.nodes[0];
        const target = p.nodes[p.nodes.length - 1];
        return (
          <button
            key={p.id}
            onClick={() => onSelect(p)}
            className={`group rounded-xl border p-3.5 text-left transition ${
              selected
                ? "border-accent/70 bg-accent/[0.06] shadow-lift"
                : "border-edge bg-panel hover:border-accent/40 hover:shadow-card"
            } ${p.suppressed ? "opacity-60" : ""}`}
          >
            <div className="flex items-center gap-2.5">
              <span
                className={`grid h-6 w-6 shrink-0 place-items-center rounded-md text-[11px] font-bold tabular-nums ${
                  selected ? "bg-accent/20 text-slate-800" : "bg-ink text-slate-500"
                }`}
              >
                {rank + 1}
              </span>
              <span className="flex min-w-0 flex-1 items-center gap-1.5 truncate text-[13px] font-medium text-slate-800">
                {p.runtimeConfirmed && (
                  <ZapIcon
                    className="h-3.5 w-3.5 shrink-0 text-red-600"
                    aria-label="Runtime-confirmed by Falco"
                  />
                )}
                <span className="truncate">
                  {entry?.name} <span className="text-slate-500">→</span> {target?.name}
                </span>
              </span>
              {p.priorityLabel && (
                <span
                  className={`shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-bold tabular-nums ${priorityTone(p.priorityLabel)}`}
                  title={
                    `Triage priority ${p.priority?.toFixed(0)}/100` +
                    (p.priorityFactors && p.priorityFactors.length
                      ? ` - ${p.priorityFactors.join(" · ")}`
                      : "")
                  }
                >
                  {p.priorityLabel}
                </span>
              )}
              {p.suppressed && (
                <span
                  className="shrink-0 rounded-md bg-slate-500/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-500"
                  title={
                    p.suppression
                      ? `Suppressed · ${p.suppression.reason} · ${p.suppression.owner}`
                      : "Suppressed"
                  }
                >
                  suppressed
                </span>
              )}
              <span
                className={`shrink-0 rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums ${scoreTone(p.score)}`}
              >
                {(p.score * 100).toFixed(0)}%
              </span>
            </div>
            <div className="mt-1.5 truncate pl-[34px] text-[11px] text-slate-500">
              {p.steps.length} hops · {p.nodes.map((n) => n.label).join(" → ")}
            </div>
          </button>
        );
      })}
    </div>
  );
}
