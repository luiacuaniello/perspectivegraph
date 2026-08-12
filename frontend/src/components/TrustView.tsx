import { useState } from "react";
import { fetchValidations, type Calibration, type CalibrationTrendPoint, type DetectionStats, type RiskSimulation, type ValidationMetrics } from "../api/client";
import { CalibrationPanel } from "./CalibrationPanel";
import InfoTip from "./InfoTip";

// Trust is the case for believing the numbers, given its own page.
//
// Every competitor shows a risk score. The thing this engine does that they do not
// is tell you how much to trust its own output - and that used to live as a dense
// research card at the bottom of the overview, readable only by whoever wrote it.
// Here it leads with a plain-language verdict, then the evidence behind it, then
// the diagnostics for the reader who wants them.

interface Props {
  calibration?: Calibration;
  trend?: CalibrationTrendPoint[];
  validation?: ValidationMetrics;
  risk?: RiskSimulation;
}

// Below this many recorded outcomes the verdict is stated but marked provisional.
//
// It is not a statistical threshold so much as an honesty one: at n=14 the 95% interval
// on an observed rate spans roughly 42%-90%, so an 11-point gap between predicted and
// observed sits comfortably inside the noise. The page used to print "Underconfident" in
// 26px while three of its own segment chips said "insufficient data" - stating as a
// measurement what its own evidence called a guess. The count now sits beside the
// verdict, where it qualifies it.
const PROVISIONAL_BELOW = 30;

export default function TrustView({ calibration, trend, validation, risk }: Props) {
  const has = calibration?.hasData;
  const provisional = has ? calibration!.samples < PROVISIONAL_BELOW : false;

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto pr-1">
      <section className="rounded-2xl border border-edge bg-panel px-5 py-5">
        <div className="text-[11px] text-muted">Verdict on the engine's own scores</div>
        <div className="mt-1.5 flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h2 className="text-[26px] font-semibold capitalize leading-none text-slate-900">
            {(calibration?.verdict ?? "not measured").replace(/-/g, " ")}
          </h2>
          {has && (
            <span
              className={`text-[12px] tabular-nums ${provisional ? "font-medium text-slate-700" : "text-muted"}`}
              title={
                provisional
                  ? `A verdict on ${calibration!.samples} outcomes. At this count the 95% interval on the observed rate is roughly ±25 points, so treat the direction as a hypothesis and keep recording.`
                  : `${calibration!.samples} recorded outcomes`
              }
            >
              on {calibration!.samples} outcome{calibration!.samples === 1 ? "" : "s"}
              {provisional ? " - provisional" : ""}
            </span>
          )}
        </div>
        <p className="mt-3 max-w-[70ch] text-[13px] leading-relaxed text-slate-600">
          {plainVerdict(calibration)}
        </p>
        {has && calibration!.diagnosis && (
          <p className="mt-3 rounded-xl bg-panel-2 px-3.5 py-2.5 text-[12px] leading-relaxed text-slate-600">
            <span className="font-medium text-slate-700">What to do: </span>
            {calibration!.diagnosis}
          </p>
        )}
      </section>

      {validation && validation.tested > 0 && (
        <section className="rounded-2xl border border-edge bg-panel px-5 py-4">
          <div className="mb-3 flex items-center gap-1 text-[11px] text-muted">
            Red-team and BAS verdicts
            <InfoTip text="Outcomes recorded against surfaced paths. Precision is how many tested paths turned out real; recall is how many real paths the engine had surfaced." />
          </div>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <Figure label="Precision" value={pct(validation.precision)} tone="text-emerald-600" />
            <Figure label="Recall" value={pct(validation.recall)} tone="text-accent" />
            <Figure label="Confirmed" value={String(validation.confirmed)} />
            <Figure label="Refuted" value={String(validation.refuted)} tone="text-amber-600" />
            <MissedFigure count={validation.missed} />
          </div>
        </section>
      )}

      {calibration?.detection && calibration.detection.tested > 0 && (
        <DetectionRow detection={calibration.detection} />
      )}

      {calibration && <CalibrationPanel calibration={calibration} trend={trend} />}

      {calibration?.edge?.hasData && <EdgeTrack edge={calibration.edge} />}

      {risk && (
        <section className="rounded-2xl border border-edge bg-panel px-5 py-4">
          <div className="mb-2 flex items-center gap-1 text-[11px] text-muted">
            Where the headline risk is uncertain
            <InfoTip text="The modeled band comes from resampling every edge probability from its evidence, so a wide band means the number rests on soft inputs rather than measurements." />
          </div>
          <p className="text-[13px] leading-relaxed text-slate-600">
            The overall compromise estimate sits at{" "}
            <span className="font-semibold text-slate-800">{pct(risk.anyCompromiseProbability)}</span>, and resampling
            the evidence puts it between{" "}
            <span className="font-semibold text-slate-800">{pct(risk.sensitivityLow)}</span> and{" "}
            <span className="font-semibold text-slate-800">{pct(risk.sensitivityHigh)}</span>.{" "}
            {bandNote(risk)}
          </p>
        </section>
      )}
    </div>
  );
}

// bandNote reads the uncertainty band honestly. A zero-width band is only
// reassuring when the estimate has room to move: pinned against 100% it means the
// metric is saturated, which is the opposite of precision and must not be
// reported as "driven by evidence".
function bandNote(risk: RiskSimulation): string {
  const width = risk.sensitivityHigh - risk.sensitivityLow;
  if (risk.anyCompromiseProbability >= 0.99) {
    return "The estimate is pinned at the top of its range, so the narrow band reflects saturation rather than precision: with this many open routes, the model cannot distinguish bad from worse. Cut routes and this number starts carrying information again.";
  }
  if (width < 0.05) {
    return "That band is tight: the estimate is driven by evidence rather than guesses.";
  }
  return "That band is wide: treat the number qualitatively until more of its edges are evidence-backed.";
}

// plainVerdict turns the calibration report into the sentence a non-statistician
// needs. The numbers are still below; this is what they mean.
function plainVerdict(c?: Calibration): string {
  if (!c?.hasData) {
    return "No outcomes have been recorded yet, so the scores are expert estimates rather than measurements. Record red-team or BAS verdicts against surfaced paths - or run the AWS oracle harness - and this page starts grading them.";
  }
  const predicted = pct(c.meanPredicted);
  const observed = pct(c.observedRate);
  if (c.verdict === "well-calibrated") {
    return `Across ${c.samples} tested routes the engine predicted ${predicted} on average and ${observed} actually held up. When it says 70%, roughly 70% is what happens - the scores can be read as probabilities.`;
  }
  if (c.verdict === "overconfident") {
    return `Across ${c.samples} tested routes the engine predicted ${predicted} on average but only ${observed} held up. It is claiming more certainty than reality delivers, so treat the ranking as sound and the absolute values as inflated.`;
  }
  if (c.verdict === "underconfident") {
    return `Across ${c.samples} tested routes the engine predicted ${predicted} on average but ${observed} held up. Reality is harsher than the model expects, so the scores understate what an attacker achieves.`;
  }
  return `Only ${c.samples} tested route${c.samples === 1 ? "" : "s"} so far - too few to judge the scores. Record more outcomes before reading the numbers as probabilities.`;
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
      <div className="mb-3 flex items-center gap-1 text-[11px] text-muted">
        Per-CVE forecasts, graded after the fact
        <InfoTip text="Sealed before the outcome existed: for each CVE that was not yet known-exploited, the engine recorded what it predicted from that day's evidence, and was graded a window later against whether the CVE entered CISA's KEV catalogue. No red team needed - it builds itself from public feeds." />
      </div>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Figure label="Forecasts graded" value={String(edge.samples)} />
        <Figure label="Said on average" value={`${said}%`} />
        <Figure label="Actually happened" value={`${hit}%`} tone="text-accent" />
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

function Figure({ label, value, tone = "text-slate-800" }: { label: string; value: string; tone?: string }) {
  return (
    <div>
      <div className={`text-[20px] font-semibold tabular-nums leading-none ${tone}`}>{value}</div>
      <div className="mt-1 text-[11px] text-muted">{label}</div>
    </div>
  );
}

function pct(v: number | null | undefined): string {
  return v == null ? "-" : `${Math.round(v * 100)}%`;
}

// "Missed" is the most informative object on this page, and it used to be a number you
// could not act on.
//
// Precision says how much noise the engine emits; recall says what it failed to see -
// and a false negative in an attack-path engine is the one error that never shows up in
// production, because nobody chases a route they were never shown. So the count opens.
//
// It expands rather than linking to a path view on purpose: a missed route is by
// definition one the engine did NOT surface, so there is no path page to link to. What
// the tester recorded - the route they walked, the tool, the evidence - is the whole
// artifact, and it is carried on the verdict itself (see Record.Route, which exists for
// exactly this case).
function MissedFigure({ count }: { count: number }) {
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState<MissedRecord[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (!next || rows) return;
    // Fetched on demand: most readers never open this, and the verdict list is the
    // heaviest thing the trust page could ask for.
    fetchValidations()
      .then((b) => setRows(b.validations.filter((v) => v.outcome === "missed") as MissedRecord[]))
      .catch((e) => setErr(e instanceof Error ? e.message : "could not load the verdicts"));
  };

  return (
    <div className="col-span-2 sm:col-span-1">
      <button
        onClick={toggle}
        disabled={count === 0}
        aria-expanded={open}
        className="text-left disabled:cursor-default"
        title={count === 0 ? "No missed routes recorded" : "Show the routes the engine did not surface"}
      >
        <div className={`text-[22px] font-semibold leading-none tabular-nums ${count > 0 ? "text-flag" : "text-slate-900"}`}>
          {count}
        </div>
        <div className="mt-1 flex items-center gap-1 text-[11px] text-muted">
          Missed
          {count > 0 && <span className="text-[10px]">{open ? "▾" : "▸"}</span>}
        </div>
      </button>

      {open && (
        <div className="col-span-full mt-3 flex flex-col gap-2">
          {err && <p className="text-[11px] text-flag">{err}</p>}
          {!err && !rows && <p className="text-[11px] text-muted">Loading…</p>}
          {rows?.length === 0 && (
            <p className="text-[11px] text-muted">
              The count says {count}, but no verdict carries the detail. Older records may predate the
              route being stored.
            </p>
          )}
          {rows?.map((r, i) => (
            <div key={r.id ?? i} className="rounded-lg border border-edge bg-panel-2 px-3 py-2">
              <div className="font-mono text-[11.5px] text-slate-900">{r.route || r.path_id || "unnamed route"}</div>
              <div className="mt-1 text-[10.5px] text-muted">
                found by {r.source || "unknown"}
                {r.tested_at ? ` · ${new Date(r.tested_at).toLocaleDateString()}` : ""}
              </div>
              {r.evidence && <div className="mt-1 text-[11px] leading-relaxed text-slate-600">{r.evidence}</div>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// The verdict records come back from REST in the store's own snake_case, not the
// GraphQL camelCase the rest of this file uses.
interface MissedRecord {
  id?: string;
  route?: string;
  path_id?: string;
  source?: string;
  evidence?: string;
  tested_at?: string;
  outcome: string;
}

// Of the routes a tester CONFIRMED exploitable, how many the detection stack caught.
//
// This needs no statistics to act on - 1 in 10 is a fact at any sample size - and it says
// something no other number here does: these routes are real AND invisible to the
// controls meant to catch them. It spent its life as a grey chip in the diagnostics row,
// at the same weight as "long-path · insufficient data".
function DetectionRow({ detection }: { detection: DetectionStats }) {
  const rate = detection.tested > 0 ? detection.detected / detection.tested : 0;
  const missedCount = detection.tested - detection.detected;
  return (
    <section className="rounded-2xl border border-edge bg-panel px-5 py-4">
      <div className="mb-2 flex items-center gap-1 text-[11px] text-muted">
        What the detection stack caught
        <InfoTip text="Of the routes a red-team or BAS run CONFIRMED exploitable and that carried a detection report, how many were caught or blocked. Unlike calibration this needs no sample size to act on: an exploitable route nobody detected is a gap whatever the count." />
      </div>
      <p className="max-w-[70ch] text-[13px] leading-relaxed text-slate-600">
        <span className="font-semibold tabular-nums text-slate-900">
          {detection.detected} of {detection.tested}
        </span>{" "}
        confirmed-exploitable route{detection.tested === 1 ? "" : "s"} {detection.detected === 1 ? "was" : "were"} caught
        ({pct(rate)}).
        {missedCount > 0 && (
          <>
            {" "}
            <span className="text-flag">
              {missedCount} {missedCount === 1 ? "was" : "were"} walked without being detected.
            </span>
          </>
        )}
        {detection.highScoreTested > 0 && (
          <> On the high-scoring ones the rate is {pct(detection.highScoreDetectionRate)}.</>
        )}
      </p>
    </section>
  );
}
