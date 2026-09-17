import type { AttackPath } from "../api/client";
import RouteActions from "./RouteActions";
import { useReadOnly } from "../auth/readOnly";
import { ZapIcon } from "./icons";
import { routeStatus } from "./routeChannels";
import { StatusPill, TargetIcon , NodeName } from "./routeChannelViews";

interface Props {
  paths: AttackPath[];
  selectedId: string | null;
  onSelect: (p: AttackPath) => void;
  // Called after a row action changed something server-side, so the queue reflects the
  // new state immediately rather than at the next poll.
  onChanged?: () => void;
}

function scoreTone(score: number): string {
  if (score >= 0.3) return "bg-red-500/15 text-flag";
  if (score >= 0.1) return "bg-amber-500/15 text-amber-700";
  return "bg-slate-500/15 text-slate-600";
}

// The list arrives sorted by composite priority, not by exploit score. Those two
// disagree often (a 90% score can sit below a 55% one, because priority also weighs
// blast radius, runtime confirmation and exposure) - so showing only the score next
// to a rank number made a correctly-ordered list look broken. These give priority
// the row's visual weight instead, and the score keeps its place one line down,
// labelled for what it is.

export default function AttackPathList({
  paths,
  selectedId,
  onSelect,
  onChanged,
}: Props) {
  const readOnly = useReadOnly();
  if (paths.length === 0) {
    return (
      <div className="rounded-xl border border-edge bg-panel shadow-card p-4 text-sm text-slate-500">
        No critical attack paths. Seed the demo with{" "}
        <code className="text-teal-700">make seed</code> to see one light up.
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
          <div
            key={p.id}
            className={`group/row relative rounded-xl border transition ${
              selected
                ? "border-accent/70 bg-accent/6 shadow-lift"
                : "border-edge bg-panel hover:border-accent/40 hover:shadow-card"
            } ${p.suppressed ? "opacity-60" : ""}`}
          >
            <button
              onClick={() => onSelect(p)}
              className="w-full p-3.5 text-left"
            >
              <div className="flex items-start gap-2.5">
                <span
                  className={`grid h-6 w-6 shrink-0 place-items-center rounded-md text-[12px] font-bold tabular-nums ${
                    selected
                      ? "bg-accent/20 text-slate-800"
                      : "bg-ink text-slate-500"
                  }`}
                >
                  {rank + 1}
                </span>
                {/* Two lines, never truncated. The row used to squeeze entry → target onto one
                    line and cut both - "edge-al… → payments-admi…" - so the one thing a
                    route is, its two ends, was the thing the list could not show. The target
                    leads, because it is what the route costs you; the entry follows with its
                    qualifier intact, since "(0.0.0.0/0)" is the difference between an
                    internal hop and something the whole internet can reach. */}
                <span className="min-w-0 flex-1">
                  <span className="flex items-start gap-1.5 text-[14px] font-medium leading-snug text-slate-800">
                    {p.runtimeConfirmed && (
                      <ZapIcon
                        className="mt-[3px] h-3.5 w-3.5 shrink-0 text-flag"
                        aria-label="Runtime-confirmed by Falco"
                      />
                    )}
                    <TargetIcon path={p} className="mt-[4px]" />
                    <NodeName name={target?.name} className="min-w-0 break-words" />
                  </span>
                  {/* The lifecycle pill rides on this line, as on Today: on line one it took
                      the width the target's name needs, and at 1024px the column is narrow
                      enough that "(AdministratorAccess)" broke in the middle of the word. */}
                  <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[12px] text-slate-500">
                    <StatusPill status={routeStatus(p)} />
                    <span className="break-words">
                      from <NodeName name={entry?.name} /> · {p.steps.length} {p.steps.length === 1 ? "hop" : "hops"}
                    </span>
                  </span>
                </span>
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
                    <span className="block text-[15px] font-semibold leading-none tabular-nums text-slate-900">
                      {p.priority.toFixed(0)}
                    </span>
                    <span className="mt-0.5 block text-[12px] font-semibold uppercase tracking-[0.06em] text-muted">
                      {p.priorityLabel ?? "priority"}
                    </span>
                  </span>
                ) : (
                  // No composite priority (older backend): the score is what orders the
                  // list, so it keeps the headline slot.
                  <span
                    className={`shrink-0 rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums ${scoreTone(p.score)}`}
                  >
                    {(p.score * 100).toFixed(0)}%
                  </span>
                )}
              </div>
              {/* Priority as a bar: why row 3 sits below row 1 becomes visible without
                opening either of them. */}
              {p.priority != null && (
                <div className="mt-2 ml-[34px] h-[3px] overflow-hidden rounded-full bg-panel-2">
                  <div
                    className="h-full rounded-full bg-slate-600"
                    style={{
                      width: `${Math.max(2, Math.min(100, p.priority))}%`,
                    }}
                  />
                </div>
              )}
            </button>
            {/* Actions sit OUTSIDE the row button - a button cannot contain buttons, and
                nesting them made the whole row one hit target where a "Triage" click also
                selected the route.

                Absolutely positioned so they cost no height while hidden: reserving the
                space made every row taller for an affordance most rows never show. They
                overlay the right end of the metadata line, which is empty. */}
            {/* Not offered at all on a read-only instance: these reveal on hover, and a
                control that appears only to refuse is noise in a list. The detail panel
                still shows its actions, disabled, with the reason. */}
            {!readOnly && (
              <div className="absolute bottom-2 right-3 flex justify-end">
                <RouteActions path={p} onChanged={() => onChanged?.()} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
