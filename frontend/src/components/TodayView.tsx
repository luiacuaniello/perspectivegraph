import type { AttackPath, Calibration, Dashboard, Fix, History, IngestSource, RiskSimulation } from "../api/client";
import InfoTip from "./InfoTip";
import { routeStatus, verdictSource } from "./routeChannels";
import { SeverityBar, StatusPill, TargetIcon , NodeName } from "./routeChannelViews";
import { ZapIcon } from "./icons";

// Today is the decision surface. The old overview opened with a tutorial, then a
// saturated "100%" that can never move, and buried the product's best sentence -
// "seven fixes eliminate the risk" - six cards down. This inverts that: the page
// answers "what is being exploited, what do I change, and should I believe it",
// in that order, and every headline number is one that MOVES when you do the work.

interface Props {
  posture: Dashboard["posture"];
  risk: RiskSimulation;
  paths: AttackPath[];
  plan: Fix[];
  violations: Dashboard["invariantViolations"];
  calibration?: Calibration;
  history?: History;
  onOpenPath: (id: string) => void;
  onSeeAllPaths: () => void;
  onOpenTrust: () => void;
  coverage?: IngestSource[] | null;
}

// TOP_FIXES is how many actions the page asks for. Three is a decision; ten is
// another backlog, which is what the product exists to eliminate.
const TOP_FIXES = 3;

export default function TodayView({
  posture,
  risk,
  paths,
  plan,
  violations,
  calibration,
  history,
  onOpenPath,
  onSeeAllPaths,
  onOpenTrust,
  coverage,
}: Props) {
  const topFixes = plan.slice(0, TOP_FIXES);
  const removable = topFixes.reduce((a, f) => a + f.coveragePct, 0);
  const pathsCovered = topFixes.reduce((a, f) => a + f.pathCount, 0);
  // Sensitive assets an attacker can currently reach at all. Unlike an
  // "account compromise %" that pins at 100, this ticks down one by one as
  // routes are cut, so a week of work is visible.
  const reachable = risk.crownJewels.filter((j) => j.compromiseProbability > 0);
  const worst = reachable[0];
  const live = paths.filter((p) => p.runtimeConfirmed);
  // The previous analysis pass, so the briefing can say which way the number moved.
  // The old KPI tile showed this as "+0 since last analysis"; a direction is worth
  // more than a delta of zero dressed as news.
  const prevOpen = history?.trend?.length && history.trend.length > 1
    ? history.trend[history.trend.length - 2].criticalPaths
    : undefined;

  // The scroll container is the wrapper App renders around this view (it also holds
  // the intro banner); repeating `overflow-y-auto h-full` here nested a second
  // scroller inside the first for no gain.
  return (
    <div className="flex flex-col gap-4">
      <Briefing
        live={live}
        reachable={reachable.length}
        worst={worst}
        openRoutes={posture.activePaths}
        fixes={topFixes.length}
        closes={pathsCovered}
        removable={removable}
        prevOpen={prevOpen}
        calibration={calibration}
        onOpenPath={onOpenPath}
        onOpenTrust={onOpenTrust}
      />

      <CoverageStrip coverage={coverage} openRoutes={posture.activePaths} />

      <section>
        <div className="mb-2 flex items-baseline justify-between">
          <h2 className="text-[15px] font-semibold text-slate-900">
            {topFixes.length > 0 ? `Do these ${topFixes.length === 1 ? "one thing" : `${topFixes.length} things`}` : "Nothing to fix"}
          </h2>
          {plan.length > topFixes.length && (
            <span className="text-[11px] text-muted">
              {plan.length - topFixes.length} more cover the rest
            </span>
          )}
        </div>
        {topFixes.length > 0 ? (
          <>
            <p className="mb-3 text-[12px] text-muted">
              They cut <span className="font-semibold text-slate-700">{Math.round(removable * 100)}%</span> of
              reachable risk across {pathsCovered} of your {posture.activePaths} routes.
            </p>
            <ol className="flex flex-col gap-2">
              {topFixes.map((f, i) => (
                <FixRow key={f.title} fix={f} rank={i + 1} />
              ))}
            </ol>
          </>
        ) : (
          <p className="rounded-xl border border-edge bg-panel px-4 py-3 text-[12px] text-muted">
            No remediation was generated for the current graph.
          </p>
        )}
      </section>

      <section>
        <div className="mb-2 flex items-baseline justify-between">
          <h2 className="flex items-center gap-1 text-[13px] font-medium text-slate-700">
            Highest-priority routes
            <InfoTip text="Ranked by composite triage priority, not by exploit score: priority also weighs what the route reaches, whether runtime confirmed it, and how exposed the entry is. So a lower-scoring route can outrank a higher-scoring one." />
          </h2>
          <button onClick={onSeeAllPaths} className="text-xs text-slate-500 transition hover:text-slate-700">
            inspect all ({posture.activePaths}) →
          </button>
        </div>
        <ul className="flex flex-col gap-1.5">
          {paths.slice(0, 3).map((p) => (
            <PathRow key={p.id} path={p} onOpen={() => onOpenPath(p.id)} />
          ))}
        </ul>
      </section>

      <div className="grid gap-3 sm:grid-cols-2">
        <TrustCard calibration={calibration} onOpen={onOpenTrust} />
        {violations.length > 0 && <ViolationCard count={violations.length} violations={violations} />}
      </div>
    </div>
  );
}

// CoverageStrip is what stops an empty board from reading as good news. Every other
// number on this page qualifies what it SHOWS; this qualifies what the engine could not
// see. A path-finding engine fed by incomplete scanners produces false negatives, and
// those are invisible - nobody chases a route they were never shown - so "0 open routes"
// has to be readable as "none in what I was given", with the given part stated. It gets
// louder when the board is empty AND a source has gone quiet, because that is exactly
// when a reader would otherwise relax.
function CoverageStrip({ coverage, openRoutes }: { coverage?: IngestSource[] | null; openRoutes: number }) {
  if (!coverage || coverage.length === 0) return null;
  const stale = coverage.filter((c) => c.stale);
  const alarming = openRoutes === 0 && stale.length > 0;
  return (
    <div
      className={`rounded-xl border px-4 py-2.5 text-[11px] ${
        alarming ? "border-slate-400 bg-panel" : "border-edge bg-panel"
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className={alarming ? "font-semibold text-slate-900" : "text-muted"}>
          {alarming ? "Nothing found - but some sources have gone quiet" : "Built from"}
        </span>
        {coverage.map((c) => (
          <span key={c.source} className={c.stale ? "font-medium text-slate-900" : "text-slate-600"}>
            {c.source}
            <span className={c.stale ? "text-slate-600" : "text-slate-400"}>
              {" "}
              {c.stale ? `silent ${c.silentFor}` : "current"}
            </span>
          </span>
        ))}
      </div>
      {alarming && (
        <p className="mt-1 text-[11px] leading-relaxed text-slate-700">
          An empty board only means "no reachable path" for the parts of the estate that were actually
          reported. A source that stopped reporting cannot show you a route it never sent.
        </p>
      )}
    </div>
  );
}

// The briefing: one sentence and one number.
//
// This replaced a red banner plus three competing KPI tiles - "sensitive assets
// reachable", "exposure removable", "open routes" - each with its own colour. Three
// numbers at equal weight is three answers to "how bad is it", and the eye picked
// whichever was reddest rather than whichever was actionable. The same facts are all
// still here; they are a sentence now, so they can only be read in one order.
//
// Red appears here and nowhere else on the page: it means a route is being walked in
// runtime, right now. Reserving it is what makes it mean something.
function Briefing({
  live,
  reachable,
  worst,
  openRoutes,
  fixes,
  closes,
  removable,
  prevOpen,
  calibration,
  onOpenPath,
  onOpenTrust,
}: {
  live: AttackPath[];
  reachable: number;
  worst?: { name: string; compromiseProbability: number };
  openRoutes: number;
  fixes: number;
  closes: number;
  removable: number;
  prevOpen?: number;
  calibration?: Calibration;
  onOpenPath: (id: string) => void;
  onOpenTrust: () => void;
}) {
  const delta = prevOpen === undefined ? 0 : openRoutes - prevOpen;
  // Who, if anyone, has a recorded verdict on the routes that runtime says are live.
  //
  // "2 routes are being walked right now" reads as an intrusion, and the reader has no
  // way to tell it from their own purple team exercising the same path - which is very
  // often what runtime traffic on a tested route actually is. Those two readings call
  // for opposite responses, and guessing between them is not something to leave to the
  // person on call at 3am. The engine already stores who recorded each verdict; this
  // just says it out loud.
  const testers = [...new Set(live.map(verdictSource).filter(Boolean))] as string[];
  // The other half of the live sentence, and the half nobody was saying.
  //
  // "2 routes are being walked right now" answers whether it is happening. The trust
  // page separately knows that 9 of 10 confirmed-exploitable routes were walked without
  // the detection stack noticing. Put together they mean: it is happening, and probably
  // nobody is watching - which is the thing a reader most needs and neither page said.
  const det = calibration?.detection;
  const blind = det && det.tested > 0 ? det.tested - det.detected : 0;
  // Provisional carries over from the trust verdict. The percentages below are computed
  // from scores the engine itself currently rates mis-scaled, and asserting 61% in bold
  // while that caveat lives two screens away is the page believing its own output more
  // than its own measurement does.
  const provisional = calibration?.hasData ? calibration.samples < 30 : false;
  // The asset's own name, without the trailing "(AdministratorAccess)" qualifier the
  // engine appends. A headline names the thing; the qualifier belongs in the detail.
  const target = live[0]?.nodes?.[live[0].nodes.length - 1]?.name?.replace(/\s*\(.*\)\s*$/, "");
  return (
    <section className="flex flex-col gap-2">
      <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted">Today</p>

      {live.length > 0 ? (
        <h1 className="max-w-[34ch] text-[22px] font-semibold leading-[1.25] tracking-[-0.02em] text-slate-900">
          {live.length} route{live.length === 1 ? " is" : "s are"} being walked
          {target ? (
            <>
              {" "}into{" "}
              <button
                onClick={() => onOpenPath(live[0].id)}
                className="text-flag underline-offset-4 hover:underline"
              >
                {target}
              </button>
            </>
          ) : null}{" "}
          right now.
        </h1>
      ) : (
        <h1 className="max-w-[34ch] text-[22px] font-semibold leading-[1.25] tracking-[-0.02em] text-slate-900">
          {reachable === 0
            ? "Nothing sensitive is reachable today."
            : `${reachable} sensitive asset${reachable === 1 ? " is" : "s are"} reachable today.`}
        </h1>
      )}

      {live.length > 0 && (
        <p className="max-w-[62ch] text-[12.5px] leading-relaxed">
          {testers.length > 0 ? (
            <span className="text-slate-700">
              {live.length === 1 ? "It carries" : "They carry"} a recorded verdict from{" "}
              <span className="font-medium text-slate-900">{testers.join(" and ")}</span> - so this
              traffic may be your own test, not an intruder.
            </span>
          ) : (
            <span className="text-flag">
              No test verdict is recorded against {live.length === 1 ? "it" : "them"}. Nobody has
              claimed this traffic.
            </span>
          )}
          {blind > 0 && det && (
            <span className="text-slate-700">
              {" "}Of the routes tested end to end, {det.detected} of {det.tested}{" "}
              {det.detected === 1 ? "was" : "were"} caught by detection - so a route like this one
              is likely to run{" "}
              <button onClick={onOpenTrust} className="font-medium text-slate-900 underline-offset-4 hover:underline">
                unseen
              </button>
              .
            </span>
          )}
        </p>
      )}

      <p className="max-w-[62ch] text-[13px] leading-relaxed text-muted">
        {live.length > 0 && reachable > 0 && (
          <>
            {reachable} sensitive asset{reachable === 1 ? " is" : "s are"} reachable in total.{" "}
          </>
        )}
        {fixes > 0 ? (
          <>
            The {fixes === 1 ? "change" : `${fixes} changes`} below close{fixes === 1 ? "s" : ""}{" "}
            <span className="font-medium text-slate-700">{closes}</span> of your{" "}
            <span className="font-medium text-slate-700">{openRoutes}</span> open route
            {openRoutes === 1 ? "" : "s"} - {Math.round(removable * 100)}% of reachable risk
            {provisional ? (
              <>
                {" "}
                <button
                  onClick={onOpenTrust}
                  className="underline decoration-dotted underline-offset-2 hover:text-slate-700"
                  title={`That percentage rests on scores the engine currently rates provisional, measured on ${calibration?.samples ?? 0} recorded outcomes. The ranking holds; the scale is what is uncertain.`}
                >
                  (provisional)
                </button>
              </>
            ) : null}
            .
          </>
        ) : (
          <>
            {openRoutes} route{openRoutes === 1 ? " is" : "s are"} open and no fix was generated for them.
          </>
        )}
        {worst ? (
          <>
            {" "}Worst reachable: {worst.name} at {Math.round(worst.compromiseProbability * 100)}%.
          </>
        ) : null}
        {delta !== 0 ? (
          <>
            {" "}
            {Math.abs(delta)} {delta > 0 ? "more" : "fewer"} than the last analysis.
          </>
        ) : null}
      </p>
    </section>
  );
}

function FixRow({ fix, rank }: { fix: Fix; rank: number }) {
  const pct = Math.round(fix.coveragePct * 100);
  return (
    <li className="flex items-center gap-3 rounded-xl border border-edge bg-panel px-4 py-3 transition hover:border-accent/50 sm:gap-5">
      <span className="w-4 shrink-0 text-[11px] tabular-nums text-muted">{rank}</span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-[13px] font-medium text-slate-900">{fix.title}</div>
        <div className="mt-0.5 truncate text-[11px] text-muted">
          {fix.kind} · cuts {fix.pathCount} route{fix.pathCount === 1 ? "" : "s"}
        </div>
      </div>
      <div className="hidden w-[34%] shrink-0 md:block" aria-hidden="true">
        <div className="h-1.5 overflow-hidden rounded-full bg-panel-2">
          <div className="h-full rounded-full bg-accent/70" style={{ width: `${Math.max(2, pct)}%` }} />
        </div>
      </div>
      <div className="w-14 shrink-0 text-right">
        <div className="text-[15px] font-semibold tabular-nums text-accent">{pct}%</div>
        <div className="text-[10px] text-muted">risk cut</div>
      </div>
    </li>
  );
}

// The section is titled "Highest-priority routes", so the number it shows has to be
// the priority - leading with the exploit score put a 90% below a 55% and made the
// ordering look arbitrary. The score stays, one step quieter and named.
function PathRow({ path, onOpen }: { path: AttackPath; onOpen: () => void }) {
  const from = path.nodes[0]?.name ?? "?";
  const to = path.nodes[path.nodes.length - 1]?.name ?? "?";
  return (
    <li>
      <button
        onClick={onOpen}
        className="flex w-full items-center gap-3 rounded-xl border border-edge bg-panel px-4 py-2.5 text-left transition hover:border-accent/50"
      >
        <StatusPill status={routeStatus(path)} />
        {path.runtimeConfirmed && (
          <ZapIcon className="h-3.5 w-3.5 shrink-0 text-flag" aria-label="being walked in runtime" />
        )}
        <span className="flex min-w-0 flex-1 items-center gap-1.5 text-[12.5px] text-slate-800">
          <NodeName name={from} className="min-w-[3.75rem] truncate [flex-shrink:3]" />
          <span className="shrink-0 text-muted">→</span>
          <TargetIcon path={path} />
          <NodeName name={to} className="min-w-[5rem] truncate [flex-shrink:1]" />
        </span>
        <SeverityBar priority={path.priority} score={path.score} />
      </button>
    </li>
  );
}
function TrustCard({ calibration, onOpen }: { calibration?: Calibration; onOpen: () => void }) {
  const has = calibration?.hasData;
  const verdict = calibration?.verdict ?? "not measured";
  const tone =
    verdict === "well-calibrated" ? "text-emerald-600" : verdict === "insufficient-data" || !has ? "text-slate-600" : "text-amber-600";
  return (
    <button
      onClick={onOpen}
      className="rounded-2xl border border-edge bg-panel px-4 py-3.5 text-left transition hover:border-accent/50"
    >
      <div className="text-[11px] text-muted">Can you trust these numbers?</div>
      <div className={`mt-1.5 text-[17px] font-semibold capitalize leading-none ${tone}`}>
        {verdict.replace(/-/g, " ")}
      </div>
      <div className="mt-1.5 text-[11px] text-muted">
        {has
          ? `measured against ${calibration!.samples} tested routes · see how →`
          : "no verdicts recorded yet · see how →"}
      </div>
    </button>
  );
}

function ViolationCard({ count, violations }: { count: number; violations: Dashboard["invariantViolations"] }) {
  const ids = [...new Set(violations.map((v) => v.invariantId))].slice(0, 3).join(", ");
  return (
    // Amber now means "New" in the status channel, so it cannot also mean "warning"
    // here - that overload is what made colour unreadable across the page. This is a
    // fact about the estate, not an alarm: it gets the same quiet card as everything
    // else, and earns attention by its number rather than by its border.
    <div className="rounded-2xl border border-edge bg-panel px-4 py-3.5">
      <div className="text-[11px] text-muted">Policy invariants broken</div>
      <div className="mt-1.5 text-[17px] font-semibold leading-none text-slate-900">{count}</div>
      <div className="mt-1.5 truncate text-[11px] text-muted">{ids}</div>
    </div>
  );
}
