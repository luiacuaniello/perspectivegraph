import { useEffect, useState } from "react";
import { fetchValidations, type AttackPath, type Calibration, type CalibrationTrendPoint, type ValidationMetrics } from "../api/client";
import { CalibrationPanel } from "./CalibrationPanel";
import InfoTip from "./InfoTip";
import { isProvisional, meaningFor, PROVISIONAL_BELOW } from "./accuracyVerdict";
import { routeLabel } from "./routeChannels";

// Accuracy is the case for believing the numbers, given its own page. It was called
// "Trust", which in a security tool reads as IAM trust policies.
//
// Every competitor shows a risk score. What this engine does that they do not is say how
// far its own output can be believed. The page answers one question - are the scores right?
// - in the order a reader needs it: the verdict, what it means for them, the evidence it
// rests on, and the statistics last, closed, for whoever wants them. Two things that used to
// share the page answer other questions and moved: what the detection stack caught is a fact
// about the estate (Today), and how uncertain the total risk is sits beside that risk.

interface Props {
  calibration?: Calibration;
  trend?: CalibrationTrendPoint[];
  validation?: ValidationMetrics;
  // The open routes, so the evidence register can name the route a verdict was recorded on.
  paths?: AttackPath[];
  onOpenPath?: (id: string) => void;
}

export default function AccuracyView({ calibration, trend, validation, paths, onOpenPath }: Props) {
  const has = calibration?.hasData;
  const provisional = isProvisional(calibration);

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto pr-1">
      <section className="rounded-2xl border border-edge bg-panel px-5 py-5">
        <div className="text-[12px] text-muted">Are the engine's scores right?</div>
        {/* Below the floor the headline is the sample size, not a verdict: a verdict in 26px
            on fourteen outcomes is a measurement claim the data cannot back. The direction is
            still given, beside the count that qualifies it. */}
        <h2 className="mt-1.5 text-[26px] font-semibold leading-tight text-slate-900">
          {provisional ? "Not enough outcomes yet" : capitalize((calibration?.verdict ?? "not measured").replace(/-/g, " "))}
        </h2>
        {has && <SampleProgress calibration={calibration!} provisional={provisional} />}
        <p className="mt-3 max-w-[70ch] text-[13px] leading-relaxed text-slate-600">{plainVerdict(calibration)}</p>
        <p className="mt-3 max-w-[70ch] rounded-xl bg-panel-2 px-3.5 py-2.5 text-[13px] leading-relaxed text-slate-700">
          <span className="font-medium text-slate-900">What this means for you: </span>
          {meaningFor(calibration)}
        </p>
      </section>

      {validation && validation.tested + validation.missed > 0 && (
        <section className="rounded-2xl border border-edge bg-panel px-5 py-4">
          <div className="mb-3 flex items-center gap-1 text-[12px] text-muted">
            The evidence: red-team and BAS outcomes
            <InfoTip text="Outcomes recorded against surfaced routes. Precision is how many tested routes turned out real; recall is how many real routes the engine had surfaced. Missed routes are ones a tester walked that the engine never showed." />
          </div>
          {/* Figures in one ink: they are facts about the evidence, not grades. Only a missed
              route is red - a route an attacker walks that the engine never showed is the one
              error that never surfaces on its own. */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <Figure label="Proven" value={String(validation.confirmed)} />
            <Figure label="Refuted" value={String(validation.refuted)} />
            <Figure label="Missed" value={String(validation.missed)} tone={validation.missed > 0 ? "text-flag" : undefined} />
            <Figure label="Precision" value={pct(validation.precision)} />
            <Figure label="Recall" value={pct(validation.recall)} />
          </div>
          <EvidenceRegister refreshKey={`${validation.tested}:${validation.missed}`} paths={paths} onOpenPath={onOpenPath} />
        </section>
      )}

      {calibration?.edge?.hasData && <EdgeTrack edge={calibration.edge} />}

      {calibration?.hasData && (
        <details className="group rounded-2xl border border-edge bg-panel">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-5 py-4 text-[13px] font-medium text-slate-800 [&::-webkit-details-marker]:hidden">
            <span>
              Calibration details
              <span className="ml-2 font-normal text-muted">reliability diagram, error scores, ranking quality, diagnosis</span>
            </span>
            <span aria-hidden="true" className="text-muted transition group-open:rotate-90">
              ›
            </span>
          </summary>
          <div className="border-t border-edge px-4 pb-4 pt-3">
            <CalibrationPanel calibration={calibration} trend={trend} bare />
          </div>
        </details>
      )}
    </div>
  );
}

// How far the sample is from the count a verdict needs, as a bar and a sentence. The count
// is the headline's qualifier, so it sits under it rather than in a stat grid below.
function SampleProgress({ calibration: c, provisional }: { calibration: Calibration; provisional: boolean }) {
  const lean = c.verdict.replace(/-/g, " ");
  return (
    <div className="mt-2.5 flex max-w-[70ch] flex-col gap-1.5">
      {provisional && (
        <div
          className="h-1.5 overflow-hidden rounded-full bg-panel-2"
          role="progressbar"
          aria-label="Outcomes recorded toward a verdict"
          aria-valuemin={0}
          aria-valuemax={PROVISIONAL_BELOW}
          aria-valuenow={c.samples}
        >
          <div className="h-full rounded-full bg-slate-600" style={{ width: `${Math.max(2, (c.samples / PROVISIONAL_BELOW) * 100)}%` }} />
        </div>
      )}
      <span
        className="text-[12px] tabular-nums text-slate-700"
        title={
          provisional
            ? `At ${c.samples} outcomes the 95% interval on the observed rate is roughly ±25 points, so treat the direction as a hypothesis and keep recording.`
            : undefined
        }
      >
        {provisional
          ? `${c.samples} of the ${PROVISIONAL_BELOW} outcomes a verdict needs · leaning ${lean}`
          : `measured on ${c.samples} outcome${c.samples === 1 ? "" : "s"}`}
      </span>
    </div>
  );
}

// plainVerdict turns the calibration report into the sentence a non-statistician
// needs. The numbers are in the details; this is what they mean.
function plainVerdict(c?: Calibration): string {
  if (!c?.hasData) {
    return "No outcomes have been recorded yet, so the scores are expert estimates rather than measurements.";
  }
  const predicted = pct(c.meanPredicted);
  const observed = pct(c.observedRate);
  // "When it says 70%, roughly 70% is what happens" is a claim about every score range, and
  // only a verdict that checked the ranges supports it. well-calibrated now requires the
  // bins to agree as well as the averages; before, a score whose outcomes did not depend on
  // it at all earned this sentence because its mean happened to match the base rate.
  if (c.verdict === "well-calibrated") {
    return `Across ${c.samples} tested routes the engine predicted ${predicted} on average and ${observed} actually held up, and the same holds within each score range. When it says 70%, roughly 70% is what happens - the scores can be read as probabilities.`;
  }
  if (c.verdict === "calibrated-on-average") {
    return `Across ${c.samples} tested routes the engine predicted ${predicted} on average and ${observed} held up - but only the average agrees. Within individual score ranges predictions and outcomes diverge (calibration error ${c.ece.toFixed(2)}), so a particular score cannot be read as a probability: a path at 70% has not been shown to happen 70% of the time.`;
  }
  if (c.verdict === "overconfident") {
    // "The ranking is sound" is a claim about ORDER, which calibration does not measure.
    // It is made only when discrimination has actually shown it.
    const ordered = c.discrimination?.verdict === "discriminates";
    return ordered
      ? `Across ${c.samples} tested routes the engine predicted ${predicted} on average but only ${observed} held up. It is claiming more certainty than reality delivers; the order has been shown to put real paths first, so treat the ranking as sound and the absolute values as inflated.`
      : `Across ${c.samples} tested routes the engine predicted ${predicted} on average but only ${observed} held up. It is claiming more certainty than reality delivers, so treat the absolute values as inflated - and whether the order itself holds up has not been shown.`;
  }
  if (c.verdict === "underconfident") {
    return `Across ${c.samples} tested routes the engine predicted ${predicted} on average but ${observed} held up. Reality is harsher than the model expects, so the scores understate what an attacker achieves.`;
  }
  return `Only ${c.samples} tested route${c.samples === 1 ? "" : "s"} so far - too few to judge the scores. Record more outcomes before reading the numbers as probabilities.`;
}

// The verdict records come back from REST in the store's own snake_case, not the
// GraphQL camelCase the rest of this file uses.
interface VerdictRecord {
  id?: string;
  outcome: string;
  source?: string;
  evidence?: string;
  route?: string;
  path_id?: string;
  tested_at?: string;
}

const OUTCOME_LABEL: Record<string, string> = {
  confirmed: "Proven",
  partial: "Partly walked",
  refuted: "Refuted",
  missed: "Missed",
};
const SHOWN = 8;

// EvidenceRegister lists what the verdict above rests on: who tested which route, when, and
// what happened. A verdict nobody can trace back to its outcomes is an assertion; this makes
// every one of them inspectable - including a missed route, the tester's own description of
// a route the engine never surfaced (there is no path page to link it to).
function EvidenceRegister({
  refreshKey,
  paths,
  onOpenPath,
}: {
  refreshKey: string;
  paths?: AttackPath[];
  onOpenPath?: (id: string) => void;
}) {
  const [rows, setRows] = useState<VerdictRecord[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [all, setAll] = useState(false);

  useEffect(() => {
    let alive = true;
    fetchValidations()
      .then((b) => {
        if (!alive) return;
        const recs = (b.validations as unknown as VerdictRecord[]).slice();
        recs.sort((a, z) => (z.tested_at ?? "").localeCompare(a.tested_at ?? ""));
        setRows(recs);
        setErr(null);
      })
      .catch((e) => alive && setErr(e instanceof Error ? e.message : "could not load the outcomes"));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  if (err) return <p className="mt-4 text-[12px] text-muted">The outcome records could not be loaded: {err}</p>;
  if (!rows) return <p className="mt-4 text-[12px] text-muted">Loading the outcome records…</p>;
  if (rows.length === 0) return null;
  const shown = all ? rows : rows.slice(0, SHOWN);

  return (
    <div className="mt-4 border-t border-edge pt-3">
      <h3 className="mb-2 text-[12px] font-medium text-slate-700">Recorded outcomes, newest first</h3>
      <ul className="flex flex-col divide-y divide-edge/70">
        {shown.map((r, i) => {
          const path = r.path_id ? paths?.find((p) => p.id === r.path_id) : undefined;
          return (
            <li key={r.id ?? i} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 py-1.5 text-[12px]">
              <span className={`w-24 shrink-0 font-medium ${r.outcome === "missed" ? "text-flag" : "text-slate-800"}`}>
                {OUTCOME_LABEL[r.outcome] ?? r.outcome}
              </span>
              <span className="min-w-0 flex-1 break-words text-slate-700">
                {path && onOpenPath ? (
                  <button onClick={() => onOpenPath(path.id)} className="text-left underline-offset-4 hover:underline">
                    {routeLabel(path)}
                  </button>
                ) : (
                  r.route || (r.path_id ? <span className="font-mono">{r.path_id}</span> : "unnamed route")
                )}
                {r.evidence && <span className="text-muted"> - {r.evidence}</span>}
              </span>
              <span className="shrink-0 text-muted">
                {r.source || "unknown source"}
                {r.tested_at ? ` · ${new Date(r.tested_at).toLocaleDateString()}` : ""}
              </span>
            </li>
          );
        })}
      </ul>
      {rows.length > SHOWN && (
        <button onClick={() => setAll(!all)} className="mt-2 text-[12px] font-medium text-slate-700 underline-offset-4 hover:underline">
          {all ? "Show the newest only" : `Show all ${rows.length}`}
        </button>
      )}
    </div>
  );
}

// EdgeTrack is the calibration that needs no red team: the engine forecasts, for each
// CVE it can see, whether that CVE will become known-exploited, and is graded a window
// later against what actually happened. Kept visually separate from the panels above
// because it grades a different quantity - the per-hop input, not a path's score - and
// it leads with what the number does NOT license, since the graded event is narrower
// than the modelled one and the level will look pessimistic for that reason alone.
function EdgeTrack({ edge }: { edge: Calibration }) {
  const hit = Math.round(edge.observedRate * 100);
  const said = Math.round(edge.meanPredicted * 100);
  return (
    <section className="rounded-2xl border border-edge bg-panel px-5 py-4">
      <div className="mb-3 flex items-center gap-1 text-[12px] text-muted">
        Per-CVE forecasts, graded after the fact
        <InfoTip text="Sealed before the outcome existed: for each CVE that was not yet known-exploited, the engine recorded what it predicted from that day's evidence, and was graded a window later against whether the CVE entered CISA's KEV catalogue. No red team needed - it builds itself from public feeds." />
      </div>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Figure label="Forecasts graded" value={String(edge.samples)} />
        <Figure label="Said on average" value={`${said}%`} />
        <Figure label="Actually happened" value={`${hit}%`} />
        <Figure label="Brier" value={edge.brier.toFixed(3)} />
      </div>
      <p className="mt-3 max-w-[70ch] text-[12px] leading-relaxed text-muted">
        Read this as <span className="font-medium text-slate-700">ranking evidence, not a score to copy</span>:
        it grades whether a CVE gets catalogued as exploited, which is rarer and slower than the
        thing the engine models - an attacker actually traversing that hop. So the level will look
        pessimistic here even when the ordering is right, and this track deliberately publishes no
        rescale. What it does tell you is whether higher-scored CVEs really do turn out exploited
        more often than lower-scored ones.
      </p>
    </section>
  );
}

function Figure({ label, value, tone = "text-slate-900" }: { label: string; value: string; tone?: string }) {
  return (
    <div>
      <div className={`text-[20px] font-semibold tabular-nums leading-none ${tone}`}>{value}</div>
      <div className="mt-1 text-[12px] text-muted">{label}</div>
    </div>
  );
}

function pct(v: number | null | undefined): string {
  return v == null ? "-" : `${Math.round(v * 100)}%`;
}

function capitalize(t: string): string {
  return t.charAt(0).toUpperCase() + t.slice(1);
}
