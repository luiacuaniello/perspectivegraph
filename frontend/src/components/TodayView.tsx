import type { AttackPath, Calibration, Dashboard, Fix, History, IngestSource, RiskSimulation } from "../api/client";
import InfoTip from "./InfoTip";
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
  const prev = history?.trend?.length ? history.trend[history.trend.length - 2] : undefined;

  // The scroll container is the wrapper App renders around this view (it also holds
  // the intro banner); repeating `overflow-y-auto h-full` here nested a second
  // scroller inside the first for no gain.
  return (
    <div className="flex flex-col gap-4">
      {live.length > 0 && <LiveStrip paths={live} onOpenPath={onOpenPath} />}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Metric
          label="Sensitive assets reachable"
          value={String(reachable.length)}
          tone="danger"
          note={worst ? `worst: ${worst.name} at ${Math.round(worst.compromiseProbability * 100)}%` : "nothing reachable"}
          hint="Distinct crown jewels an attacker can reach by some route today. It drops as you cut paths, so progress is visible - unlike a saturated overall risk percentage."
        />
        <Metric
          label="Exposure removable today"
          value={`${Math.round(removable * 100)}%`}
          tone="accent"
          note={topFixes.length ? `with the ${topFixes.length} changes below` : "no fixes generated"}
          hint="Share of critical-path risk the top changes below eliminate, measured by the same engine that found the paths."
        />
        <Metric
          label="Open routes"
          value={String(posture.activePaths)}
          tone={posture.activePaths > 0 ? "warn" : "muted"}
          note={
            prev
              ? `${posture.activePaths - prev.criticalPaths >= 0 ? "+" : ""}${posture.activePaths - prev.criticalPaths} since last analysis`
              : `${posture.nodes} assets mapped`
          }
          hint="Routes from internet exposure to a sensitive asset that are currently open. Suppressed routes are excluded."
        />
      </div>

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
        alarming ? "border-amber-500/40 bg-amber-500/[0.07]" : "border-edge bg-panel"
      }`}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className={alarming ? "font-medium text-amber-700" : "text-muted"}>
          {alarming ? "Nothing found - but some sources have gone quiet" : "Built from"}
        </span>
        {coverage.map((c) => (
          <span key={c.source} className={c.stale ? "text-amber-700" : "text-slate-600"}>
            {c.source}
            <span className={c.stale ? "text-amber-700/75" : "text-slate-400"}>
              {" "}
              {c.stale ? `silent ${c.silentFor}` : "current"}
            </span>
          </span>
        ))}
      </div>
      {alarming && (
        <p className="mt-1 text-[11px] leading-relaxed text-amber-700/80">
          An empty board only means "no reachable path" for the parts of the estate that were actually
          reported. A source that stopped reporting cannot show you a route it never sent.
        </p>
      )}
    </div>
  );
}

// LiveStrip is the only thing allowed above the fold besides the metrics: a route
// that runtime confirms is being exercised is not a backlog item, it is now.
function LiveStrip({ paths, onOpenPath }: { paths: AttackPath[]; onOpenPath: (id: string) => void }) {
  return (
    <button
      onClick={() => onOpenPath(paths[0].id)}
      className="flex items-center gap-3 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-left transition hover:border-red-500/70"
    >
      <ZapIcon className="h-4 w-4 shrink-0 text-red-600" />
      <span className="flex-1 text-[13px] text-red-700">
        <span className="font-semibold">
          {paths.length} route{paths.length === 1 ? " is" : "s are"} being exercised right now
        </span>
        <span className="text-red-700/75"> - runtime confirmed, not theoretical</span>
      </span>
      <span className="shrink-0 text-[11px] text-red-700/80">investigate →</span>
    </button>
  );
}

function Metric({
  label,
  value,
  note,
  tone,
  hint,
}: {
  label: string;
  value: string;
  note: string;
  tone: "danger" | "accent" | "warn" | "muted";
  hint: string;
}) {
  const toneClass =
    tone === "danger" ? "text-red-600" : tone === "accent" ? "text-accent" : tone === "warn" ? "text-amber-600" : "text-slate-700";
  return (
    <div className="rounded-2xl border border-edge bg-panel px-4 py-3.5">
      <div className="flex items-center gap-1 text-[11px] text-muted">
        {label}
        <InfoTip text={hint} />
      </div>
      <div className={`mt-1.5 text-[30px] font-semibold leading-none tabular-nums ${toneClass}`}>{value}</div>
      <div className="mt-1.5 text-[11px] text-muted">{note}</div>
    </div>
  );
}

// On a wide screen the title sat far left and the percentage far right with dead
// space between, which made 31% / 20% / 11% hard to weigh against each other. The
// gutter now carries the comparison itself.
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
  // -700 shades: amber-600 at this size measures 3.2:1 on the light canvas and fails
  // WCAG AA. index.css re-lightens the -700 text shades for dark mode.
  const band =
    path.priorityLabel === "P1" ? "text-red-700" : path.priorityLabel === "P2" ? "text-amber-700" : "text-slate-600";
  return (
    <li>
      <button
        onClick={onOpen}
        className="flex w-full items-center gap-3 rounded-xl border border-edge bg-panel px-4 py-2.5 text-left transition hover:border-accent/50"
      >
        {path.runtimeConfirmed && <ZapIcon className="h-3.5 w-3.5 shrink-0 text-red-600" />}
        <span className="flex min-w-0 flex-1 items-center gap-1.5 text-[12.5px] text-slate-800">
          <span className="min-w-[3.75rem] truncate [flex-shrink:3]">{from}</span>
          <span className="shrink-0 text-muted">→</span>
          <span className="min-w-[5rem] truncate [flex-shrink:1]">{to}</span>
        </span>
        <span className="shrink-0 text-[11px] tabular-nums text-muted">exploit {Math.round(path.score * 100)}%</span>
        {path.priority != null ? (
          <span
            className={`shrink-0 text-[13px] font-semibold tabular-nums ${band}`}
            title={`Triage priority ${path.priority.toFixed(0)}/100 (${path.priorityLabel ?? "unbanded"}) - this is what ranks the list`}
          >
            {path.priority.toFixed(0)}
          </span>
        ) : (
          <span className="shrink-0 text-[12px] font-semibold tabular-nums text-red-600">
            {Math.round(path.score * 100)}%
          </span>
        )}
      </button>
    </li>
  );
}

// TrustCard is the honesty layer as a headline, not a footnote: one sentence a
// non-statistician can act on, with the diagnostics one click away.
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
    <div className="rounded-2xl border border-amber-500/30 bg-amber-500/[0.07] px-4 py-3.5">
      <div className="text-[11px] text-amber-700/80">Policy invariants broken</div>
      <div className="mt-1.5 text-[17px] font-semibold leading-none text-amber-700">{count}</div>
      <div className="mt-1.5 truncate text-[11px] text-amber-700/75">{ids}</div>
    </div>
  );
}
