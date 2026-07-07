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
        No policy invariants violated - the environment matches its architectural rules.
      </div>
    );
  }

  // Group by rule: the same invariant fires once per offending subgraph, so a flat
  // list repeats the rule name and description N times and the only thing that
  // differs - the offending nodes - is buried. One card per rule, described once,
  // with the instances listed compactly beneath it.
  const groups = new Map<string, Violation[]>();
  for (const v of violations) {
    const arr = groups.get(v.invariantId) ?? [];
    arr.push(v);
    groups.set(v.invariantId, arr);
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted">
        Architectural rules the environment breaks - forbidden graph shapes (e.g. “the internet must never reach a crown
        jewel”). Each lists the offending nodes.
      </p>
      {[...groups.values()].map((group) => {
        const head = group[0];
        return (
          <div key={head.invariantId} className="rounded-xl border border-edge bg-panel p-4">
            <div className="flex flex-wrap items-center gap-2.5">
              <Badge tone={severityTone(head.severity)} className="font-bold uppercase">
                {head.severity}
              </Badge>
              <code className="text-sm font-medium text-slate-800">{head.invariantId}</code>
              {group.length > 1 && (
                <span className="text-[11px] tabular-nums text-muted">{group.length} instances</span>
              )}
            </div>
            {head.description && <p className="mt-2 text-xs leading-relaxed text-muted">{head.description}</p>}
            <div className="mt-3 flex flex-col">
              {group.map((v, i) => (
                <div
                  key={i}
                  className="flex flex-wrap items-center gap-1.5 border-t border-edge/60 py-2 first:border-t-0 first:pt-0"
                >
                  {group.length > 1 && (
                    <span className="w-4 shrink-0 text-[11px] tabular-nums text-slate-500">{i + 1}</span>
                  )}
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
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
