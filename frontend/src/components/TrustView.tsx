import type { Calibration, CalibrationTrendPoint, RiskSimulation, ValidationMetrics } from "../api/client";
import { CalibrationPanel } from "./PostureOverview";
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

export default function TrustView({ calibration, trend, validation, risk }: Props) {
  const has = calibration?.hasData;

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-y-auto pr-1">
      <section className="rounded-2xl border border-edge bg-panel px-5 py-5">
        <div className="text-[11px] text-muted">Verdict on the engine's own scores</div>
        <h2 className="mt-1.5 text-[26px] font-semibold capitalize leading-none text-slate-900">
          {(calibration?.verdict ?? "not measured").replace(/-/g, " ")}
        </h2>
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
            <Figure label="Missed" value={String(validation.missed)} tone="text-red-600" />
          </div>
        </section>
      )}

      {calibration && <CalibrationPanel calibration={calibration} trend={trend} />}

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
