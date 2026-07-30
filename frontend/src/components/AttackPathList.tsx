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

// The list arrives sorted by composite priority, not by exploit score. Those two
// disagree often (a 90% score can sit below a 55% one, because priority also weighs
// blast radius, runtime confirmation and exposure) - so showing only the score next
// to a rank number made a correctly-ordered list look broken. These give priority
// the row's visual weight instead, and the score keeps its place one line down,
// labelled for what it is.
// The -700 shades, not -600: at 15px semibold on the light canvas, amber-600 lands
// at 3.2:1 and fails WCAG AA, while amber-700 clears 4.5:1. Dark mode is unaffected -
// index.css already remaps the -700 text shades to light ones on dark surfaces.
function priorityText(label?: string | null): string {
  if (label === "P1") return "text-red-700";
  if (label === "P2") return "text-amber-700";
  return "text-slate-600";
}

function priorityBar(label?: string | null): string {
  if (label === "P1") return "bg-red-500/70";
  if (label === "P2") return "bg-amber-500/70";
  return "bg-slate-400/60";
}

// In the truncating list, strip the entry's trailing parenthetical (e.g. the
// "(0.0.0.0/0)" CIDR) so the more important target name isn't what gets cut. The
// full entry is on the detail panel and the graph.
function shortEntry(name?: string): string {
  return (name ?? "").replace(/\s*\([^)]*\)\s*$/, "");
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
                ? "border-accent/70 bg-accent/6 shadow-lift"
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
              {/* The target is the crown jewel - the part of the route that must survive
                  truncation - so the entry gives up space three times faster. */}
              <span className="flex min-w-0 flex-1 items-center gap-1.5 text-[13px] font-medium text-slate-800">
                {p.runtimeConfirmed && (
                  <ZapIcon
                    className="h-3.5 w-3.5 shrink-0 text-red-600"
                    aria-label="Runtime-confirmed by Falco"
                  />
                )}
                <span className="min-w-[3.75rem] truncate [flex-shrink:3]">{shortEntry(entry?.name)}</span>
                <span className="shrink-0 text-slate-500">→</span>
                <span className="min-w-[5rem] truncate [flex-shrink:1]">{target?.name}</span>
              </span>
              {p.suppressed && (
                <span
                  className="shrink-0 rounded-md bg-slate-500/15 px-1.5 py-0.5 text-[10px] font-medium text-slate-500"
                  title={
                    p.suppression
                      ? `Suppressed · ${p.suppression.reason} · ${p.suppression.owner}`
                      : "Suppressed"
                  }
                >
                  suppressed
                </span>
              )}
              {p.priority != null ? (
                <span
                  className="shrink-0 text-right"
                  title={
                    `Triage priority ${p.priority.toFixed(0)}/100 - this is what ranks the list` +
                    (p.priorityFactors && p.priorityFactors.length
                      ? `: ${p.priorityFactors.join(" · ")}`
                      : "")
                  }
                >
                  <span className={`block text-[15px] font-semibold leading-none tabular-nums ${priorityText(p.priorityLabel)}`}>
                    {p.priority.toFixed(0)}
                  </span>
                  <span className="mt-0.5 block text-[9px] font-semibold uppercase tracking-[0.08em] text-muted">
                    {p.priorityLabel ?? "priority"}
                  </span>
                </span>
              ) : (
                // No composite priority (older backend): the score is what orders the
                // list, so it keeps the headline slot.
                <span className={`shrink-0 rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums ${scoreTone(p.score)}`}>
                  {(p.score * 100).toFixed(0)}%
                </span>
              )}
            </div>
            {/* Priority as a bar: why row 3 sits below row 1 becomes visible without
                opening either of them. */}
            {p.priority != null && (
              <div className="mt-2 ml-[34px] h-[3px] overflow-hidden rounded-full bg-panel-2">
                <div
                  className={`h-full rounded-full ${priorityBar(p.priorityLabel)}`}
                  style={{ width: `${Math.max(2, Math.min(100, p.priority))}%` }}
                />
              </div>
            )}
            <div className="mt-1.5 truncate pl-[34px] text-[11px] text-slate-500">
              {p.steps.length} hops
              {p.priority != null && (
                <>
                  {" · "}
                  <span className={p.score >= 0.3 ? "text-red-600" : ""}>exploit {(p.score * 100).toFixed(0)}%</span>
                </>
              )}
              {" · "}
              {p.nodes.map((n) => n.label).join(" → ")}
            </div>
          </button>
        );
      })}
    </div>
  );
}
