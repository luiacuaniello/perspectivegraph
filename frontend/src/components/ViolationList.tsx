import type { Violation } from "../api/client";
import { CheckIcon, GemIcon, GlobeIcon } from "./icons";
import Badge, { type Tone } from "./ui/Badge";

function severityTone(severity: string): Tone {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "danger";
    case "HIGH":
    case "MEDIUM":
      return "warn";
    default:
      return "neutral";
  }
}

export default function ViolationList({ violations }: { violations: Violation[] }) {
  if (violations.length === 0) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/[0.06] p-5 text-sm text-emerald-700">
        <CheckIcon className="h-4 w-4 shrink-0" />
        No policy invariants violated — the environment matches its architectural rules.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted">
        Architectural rules the environment breaks — forbidden graph shapes (e.g. “the internet must never reach a crown
        jewel”). Each lists the offending nodes.
      </p>
      {violations.map((v, i) => (
        <div key={`${v.invariantId}-${i}`} className="rounded-xl border border-edge bg-panel shadow-card p-4">
          <div className="flex flex-wrap items-center gap-2.5">
            <Badge tone={severityTone(v.severity)} className="font-bold uppercase">
              {v.severity}
            </Badge>
            <code className="text-sm font-medium text-slate-800">{v.invariantId}</code>
          </div>
          {v.description && <p className="mt-2 text-xs leading-relaxed text-muted">{v.description}</p>}
          {v.nodes.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Offending nodes</span>
              {v.nodes.map((n) => (
                <span
                  key={n.id}
                  className="inline-flex items-center gap-1 rounded-md border border-edge bg-ink px-2 py-1 text-[11px] text-slate-600"
                >
                  <span className="text-slate-400">{n.label} ·</span>
                  {n.name}
                  {n.internetExposed && <GlobeIcon className="h-3 w-3 text-accent" />}
                  {n.crownJewel && <GemIcon className="h-3 w-3 text-amber-700" />}
                </span>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
