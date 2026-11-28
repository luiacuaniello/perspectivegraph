import { useState } from "react";
import type { AttackPath } from "../api/client";
import InfoTip from "./InfoTip";
import { techniqueCounts } from "./techniques";

// Which MITRE ATT&CK techniques the open routes use, and on how many routes each. The
// detail shows a route's techniques hop by hop; this turns them around for whoever writes
// detections: a rule for the technique at the top watches the most routes at once.
//
// The list is the dashboard's own (the top routes by priority, with suppressed ones only
// when shown), so the card says when that is not every open route.

const SHOWN = 5;

export default function AttackTechniques({ paths, openRoutes }: { paths: AttackPath[]; openRoutes: number }) {
  const [all, setAll] = useState(false);
  const counts = techniqueCounts(paths);
  if (counts.length === 0) return null;
  const shown = all ? counts : counts.slice(0, SHOWN);

  return (
    <section aria-labelledby="attack-techniques" className="min-w-0 rounded-2xl border border-edge bg-panel px-4 py-3.5">
      <h2 id="attack-techniques" className="flex items-center gap-1 text-[12px] font-normal text-muted">
        ATT&CK techniques on these routes
        <InfoTip text="The MITRE ATT&CK techniques the hops of the open routes map to, and how many routes use each. A detection for a technique near the top watches the most routes. The mapping is the engine's, by the kind of hop: a technique a hop could use, not one seen in use." />
      </h2>
      <ol className="mt-2 flex flex-col gap-1.5">
        {shown.map(({ technique: t, routes }) => (
          <li key={t.id} className="flex items-baseline gap-2">
            <a
              href={t.url}
              target="_blank"
              rel="noopener noreferrer"
              aria-label={`${t.id}, ${t.name}, on MITRE ATT&CK`}
              className="shrink-0 font-mono text-[12px] text-accent underline-offset-2 hover:underline"
            >
              {t.id}
            </a>
            <span className="min-w-0 flex-1 truncate text-[13px] text-slate-700" title={`${t.name} · tactic: ${t.tactic}`}>
              {t.name}
            </span>
            <span className="shrink-0 text-[12px] tabular-nums text-muted">
              {routes} {routes === 1 ? "route" : "routes"}
            </span>
          </li>
        ))}
      </ol>
      <div className="mt-2 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 text-[12px] text-muted">
        {paths.length < openRoutes ? <span>Across the top {paths.length} of {openRoutes} open routes.</span> : <span />}
        {counts.length > SHOWN && (
          <button type="button" onClick={() => setAll((v) => !v)} className="text-slate-500 transition hover:text-slate-700">
            {all ? "Show fewer" : `Show all ${counts.length}`}
          </button>
        )}
      </div>
    </section>
  );
}
