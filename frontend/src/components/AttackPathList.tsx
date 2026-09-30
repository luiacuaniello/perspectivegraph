import { useId, useState } from "react";
import type { AttackPath } from "../api/client";
import RouteActions from "./RouteActions";
import { useReadOnly } from "../auth/readOnly";
import { ChevronRightIcon, ZapIcon } from "./icons";
import { groupByTarget, routeStatus } from "./routeChannels";
import { StatusPill, TargetIcon, NodeName } from "./routeChannelViews";

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
  if (score >= 0.1) return "bg-amber-500/15 text-amber-800";
  return "bg-slate-500/15 text-slate-600";
}

// The list arrives sorted by composite priority, not by exploit score. Those two disagree
// often (a 90% score can sit below a 55% one, because priority also weighs blast radius,
// runtime confirmation and exposure) - so a row leads with the priority and its band, and
// the exploit score lives in the detail. The score takes the headline slot only from an
// older backend that sends no priority, because then it is what orders the list.
//
// Rows are grouped by the sensitive asset they reach (see groupByTarget): a group is one
// thing you stand to lose, its lines the ways in, most urgent first.

export default function AttackPathList({ paths, selectedId, onSelect, onChanged }: Props) {
  const readOnly = useReadOnly();
  const uid = useId();
  // The reader's last open/close of the refuted section, and the route chosen when they
  // made it. Their choice holds while they move around the list; a refuted route chosen
  // afresh - a link to it, a click from Today - opens the section, since a selection hidden
  // in a closed section reads as nothing happening.
  const [refutedToggle, setRefutedToggle] = useState<{ open: boolean; at: string | null } | null>(null);

  if (paths.length === 0) {
    return (
      <div className="rounded-xl border border-edge bg-panel shadow-card p-4 text-sm text-slate-500">
        No critical attack paths. Seed the demo with{" "}
        <code className="font-mono text-slate-700">make seed</code> to see one light up.
      </div>
    );
  }

  const { groups, refuted } = groupByTarget(paths);
  const selectedRefuted = refuted.some((p) => p.id === selectedId);
  const showRefuted = selectedRefuted
    ? refutedToggle?.at === selectedId
      ? refutedToggle.open
      : true
    : (refutedToggle?.open ?? false);
  const line = (p: AttackPath, withTarget: boolean) => (
    <li key={p.id}>
      <RouteLine
        path={p}
        selected={p.id === selectedId}
        withTarget={withTarget}
        readOnly={!!readOnly}
        onSelect={onSelect}
        onChanged={onChanged}
      />
    </li>
  );

  return (
    <div className="flex flex-col gap-2">
      {groups.map((g, i) => {
        const headingId = `${uid}-asset-${i}`;
        const holdsSelection = g.routes.some((p) => p.id === selectedId);
        return (
          <section
            key={g.key}
            aria-labelledby={headingId}
            className={`rounded-xl border bg-panel transition ${
              holdsSelection ? "border-accent/60 shadow-lift" : "border-edge"
            }`}
          >
            <h3 id={headingId} className="flex items-start gap-2.5 px-3.5 pt-3 text-[14px] font-medium leading-snug text-slate-800">
              <span className="grid h-6 w-6 shrink-0 place-items-center rounded-md bg-ink text-[12px] font-bold tabular-nums text-slate-500">
                {i + 1}
              </span>
              <TargetIcon path={g.routes[0]} className="mt-[5px]" />
              {/* Never truncated: "(AdministratorAccess)" is what makes it serious. */}
              <NodeName name={g.target?.name} className="min-w-0 flex-1 break-words pt-[2px]" />
              {g.routes.length > 1 && (
                <span className="shrink-0 pt-[3px] text-[12px] font-normal text-muted">{g.routes.length} routes</span>
              )}
            </h3>
            <ul className="mt-1 flex flex-col gap-0.5 px-1.5 pb-1.5">{g.routes.map((p) => line(p, false))}</ul>
          </section>
        );
      })}

      {refuted.length > 0 && (
        // Set apart and quieter, not hidden: a refuted route is evidence against the engine,
        // and the place to act on it is here - suppress it as a false positive, or re-test.
        <section aria-labelledby={`${uid}-refuted`} className="mt-2">
          <h3 id={`${uid}-refuted`}>
            <button
              type="button"
              aria-expanded={showRefuted}
              aria-controls={`${uid}-refuted-list`}
              onClick={() => setRefutedToggle({ open: !showRefuted, at: selectedId })}
              className="flex w-full items-center gap-1.5 rounded-md px-1 py-1.5 text-left text-[12px] font-medium text-slate-500 transition hover:text-slate-700"
            >
              <ChevronRightIcon className={`h-3.5 w-3.5 transition ${showRefuted ? "rotate-90" : ""}`} />
              Refuted by tests ({refuted.length})
              <span className="font-normal text-muted">- a tester could not walk these</span>
            </button>
          </h3>
          {showRefuted && (
            <ul id={`${uid}-refuted-list`} className="mt-1 flex flex-col gap-1 rounded-xl border border-edge bg-panel p-1.5">
              {refuted.map((p) => line(p, true))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}

function RouteLine({
  path: p,
  selected,
  withTarget,
  readOnly,
  onSelect,
  onChanged,
}: {
  path: AttackPath;
  selected: boolean;
  // Inside an asset group the heading names the target; set apart (refuted) it is named here.
  withTarget: boolean;
  readOnly: boolean;
  onSelect: (p: AttackPath) => void;
  onChanged?: () => void;
}) {
  const entry = p.nodes[0];
  const target = p.nodes[p.nodes.length - 1];
  return (
    <div
      className={`group/row relative rounded-lg transition ${
        selected ? "bg-accent/6 ring-1 ring-accent/50" : "hover:bg-panel-2/60"
      } ${p.suppressed ? "opacity-60" : ""}`}
    >
      <button
        type="button"
        data-route-id={p.id}
        aria-current={selected ? "true" : undefined}
        onClick={() => onSelect(p)}
        className="w-full px-2 py-2 text-left"
      >
        {withTarget ? (
          <span className="mb-1 flex items-start gap-1.5 text-[13px] font-medium leading-snug text-slate-700">
            <TargetIcon path={p} className="mt-[4px]" />
            <NodeName name={target?.name} className="min-w-0 break-words" />
          </span>
        ) : (
          // The heading carries the target for the eye; the button still needs it for the
          // ear, or every line in a group is announced as the same "from edge-alb". The comma
          // and the space outside the span: a trailing space inside it is dropped from the
          // accessible name, which then read "account-adminfrom edge-alb".
          <>
            <span className="sr-only">{target?.name},</span>{" "}
          </>
        )}
        <span className="flex items-start gap-2">
          <span className="flex min-w-0 flex-1 items-start gap-1.5 text-[13px] leading-snug text-slate-700">
            {p.runtimeConfirmed && (
              <ZapIcon className="mt-[2px] h-3.5 w-3.5 shrink-0 text-flag" aria-label="Runtime-confirmed by Falco" />
            )}
            <span className="min-w-0 break-words">
              {p.directAccess ? (
                <>open to anyone · direct access</>
              ) : (
                <>
                  from <NodeName name={entry?.name} /> · {p.steps.length} {p.steps.length === 1 ? "hop" : "hops"}
                </>
              )}
            </span>
          </span>
          {p.priority != null ? (
            <span
              className="shrink-0 text-right"
              title={
                `Triage priority ${p.priority.toFixed(0)}/100 - this is what ranks the list` +
                (p.priorityFactors && p.priorityFactors.length ? `: ${p.priorityFactors.join(" · ")}` : "")
              }
            >
              <span className="block text-[15px] font-semibold leading-none tabular-nums text-slate-900">
                {p.priority.toFixed(0)}
              </span>
              <span className="mt-0.5 block text-[12px] font-semibold text-muted">
                {p.priorityLabel ?? "priority"}
              </span>
            </span>
          ) : (
            <span className={`shrink-0 rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums ${scoreTone(p.score)}`}>
              {(p.score * 100).toFixed(0)}%
            </span>
          )}
        </span>
        {/* The lifecycle on a line of its own, so the actions below can overlay its empty
            right end instead of reserving width every line would pay for. */}
        <span className="mt-1 flex">
          <StatusPill status={routeStatus(p)} />
        </span>
      </button>
      {/* Actions sit OUTSIDE the line's button - a button cannot contain buttons, and nesting
          them made the whole row one hit target where a "Triage" click also selected the
          route. Not offered at all when this tab cannot write: they reveal on hover, and a
          control that appears only to refuse is noise in a list. The detail panel still
          shows its actions, disabled, with the reason. */}
      {!readOnly && (
        <div className="absolute bottom-1.5 right-2 flex justify-end">
          <RouteActions path={p} onChanged={() => onChanged?.()} />
        </div>
      )}
    </div>
  );
}
