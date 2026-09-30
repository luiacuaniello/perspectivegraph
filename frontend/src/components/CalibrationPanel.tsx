import { type Calibration, type CalibrationTrendPoint } from "../api/client";
import InfoTip from "./InfoTip";
import { DiscriminationRow } from "./DiscriminationRow";
import { isProvisional } from "./accuracyVerdict";

// Sparkline draws a tiny trend line for a numeric series. It is normalised to its own range
// so a change reads at a glance - which is also why it never stands alone: the caller prints
// the first and last values beside it, or a flat line and a steep one look the same size.
function Sparkline({ values, tone }: { values: number[]; tone: string }) {
  if (values.length < 2) return null;
  const w = 240;
  const h = 32;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const pts = values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * w;
      const y = h - ((v - min) / span) * (h - 4) - 2;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  // h-full, not a fixed h-8: the caller owns the height. Hard-coding 32px here made
  // the sparkline overflow the 24px slot the calibration panel gives it, which is why
  // it collided with the diagram below.
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-full w-full" aria-hidden="true">
      <polyline points={pts} fill="none" stroke={tone} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// Verdict badges in the page's colour vocabulary: neutral for a clean result, amber for
// anything short of one (uncertain), red only where the order points the wrong way (see
// DiscriminationRow). Green is kept for "defended or fixed" and a calibration verdict is
// neither - it was green here, which read as "the estate is fine".
const VERDICT_STYLE: Record<string, { label: string; cls: string }> = {
  "well-calibrated": { label: "well-calibrated", cls: "bg-slate-500/15 text-slate-800" },
  // The mean agrees and the bins do not: not a success, and not the absence of data either -
  // without its own entry it would fall back to "insufficient data".
  "calibrated-on-average": { label: "calibrated on average", cls: "bg-amber-500/15 text-amber-800" },
  overconfident: { label: "overconfident", cls: "bg-amber-500/15 text-amber-800" },
  underconfident: { label: "underconfident", cls: "bg-amber-500/15 text-amber-800" },
  "insufficient-data": { label: "insufficient data", cls: "bg-slate-500/10 text-slate-600" },
};

// Wilson's 95% interval on a bin's observed rate. A bin of three outcomes at 67% could be
// anywhere from about 21% to 94%, and a dot drawn without that says it is exactly 67%.
function wilson(rate: number, n: number): [number, number] {
  if (n <= 0) return [0, 1];
  const z = 1.96;
  const z2 = z * z;
  const centre = (rate + z2 / (2 * n)) / (1 + z2 / n);
  const half = (z * Math.sqrt((rate * (1 - rate)) / n + z2 / (4 * n * n))) / (1 + z2 / n);
  return [Math.max(0, centre - half), Math.min(1, centre + half)];
}

// ReliabilityDiagram plots predicted (x) against observed (y) per bin over the unit
// square, with the y=x diagonal as "perfect calibration". A dot above the line is
// underconfident, below overconfident. Each dot carries its 95% interval and the count of
// outcomes behind it: without them a bin of two read with the authority of a bin of two
// hundred, and the axes had no scale to read a position against.
//
// Sized h-auto/w-full so the viewBox aspect sets the height and the drawing fills its
// box. At the previous fixed h-44 the artwork letterboxed inside a wide column.
function ReliabilityDiagram({ bins }: { bins: Calibration["bins"] }) {
  // Margins sized for the tick labels: at 34 the "100%" on the y axis ran into the rotated
  // "observed", and the last x tick was clipped at the right edge.
  const L = 48, R = 200, T = 10, B = 168; // plot box inside a 216x200 viewBox
  const x = (p: number) => L + p * (R - L);
  const y = (o: number) => B - o * (B - T);
  const populated = bins.filter((b) => b.count > 0);
  const muted = "rgb(var(--c-muted))";
  const ticks = [0, 0.5, 1];
  return (
    <svg
      viewBox="0 0 216 200"
      className="h-auto w-full"
      role="img"
      aria-label={`Reliability diagram: ${populated
        .map((b) => `predicted ${Math.round(b.meanPredicted * 100)}%, observed ${Math.round(b.observedRate * 100)}% over ${b.count}`)
        .join("; ")}`}
    >
      <rect x={L} y={T} width={R - L} height={B - T} fill="none" stroke="rgb(var(--c-edge))" strokeWidth={1} rx={3} />
      {ticks.map((t) => (
        <g key={t}>
          <line x1={x(t)} y1={B} x2={x(t)} y2={B + 3} stroke={muted} strokeWidth={1} />
          <text x={x(t)} y={B + 12} textAnchor="middle" fontSize={9} fill={muted}>
            {Math.round(t * 100)}%
          </text>
          <line x1={L - 3} y1={y(t)} x2={L} y2={y(t)} stroke={muted} strokeWidth={1} />
          <text x={L - 5} y={y(t) + 3} textAnchor="end" fontSize={9} fill={muted}>
            {Math.round(t * 100)}%
          </text>
        </g>
      ))}
      <line x1={x(0)} y1={y(0)} x2={x(1)} y2={y(1)} stroke="rgb(var(--c-muted) / 0.45)" strokeWidth={1} strokeDasharray="3 3" />
      {populated.map((b, i) => {
        const [lo, hi] = wilson(b.observedRate, b.count);
        const cx = x(b.meanPredicted);
        return (
          <g key={i}>
            <line x1={cx} y1={y(lo)} x2={cx} y2={y(hi)} stroke="rgb(var(--c-slate-600) / 0.55)" strokeWidth={2} strokeLinecap="round" />
            <circle cx={cx} cy={y(b.observedRate)} r={3.5} fill="rgb(var(--c-slate-800))" />
            <text x={cx + 6} y={y(b.observedRate) + 3} fontSize={9} fill={muted}>
              {b.count}
            </text>
          </g>
        );
      })}
      <text x={(L + R) / 2} y={196} textAnchor="middle" fontSize={10} fill={muted}>
        predicted
      </text>
      <text x={9} y={(T + B) / 2} textAnchor="middle" fontSize={10} fill={muted} transform={`rotate(-90 9 ${(T + B) / 2})`}>
        observed
      </text>
    </svg>
  );
}

function Stat({ label, value, tip }: { label: string; value: string; tip?: string }) {
  return (
    <div>
      <div className="flex items-center gap-1 text-[12px] text-muted">
        {label}
        {tip && <InfoTip text={tip} />}
      </div>
      <div className="mt-0.5 text-[15px] font-semibold tabular-nums text-slate-800">{value}</div>
    </div>
  );
}

// CalibrationPanel is the statistics behind the Accuracy verdict: whether the engine's
// predicted path scores match observed red-team/BAS outcomes, so an operator can defend
// "55%" as a probability rather than a label. Hidden until at least one tested verdict
// carries a predicted score. `bare` drops its own card when a caller already frames it.
export function CalibrationPanel({
  calibration,
  trend,
  bare = false,
}: {
  calibration: Calibration;
  trend?: CalibrationTrendPoint[];
  bare?: boolean;
}) {
  if (!calibration?.hasData) return null;
  // Below the sample floor the page headlines "Not enough outcomes yet"; a badge here
  // announcing "underconfident" in colour contradicted it one scroll down.
  const provisional = isProvisional(calibration);
  const v = provisional
    ? { label: "provisional", cls: "bg-slate-500/10 text-slate-600" }
    : (VERDICT_STYLE[calibration.verdict] ?? VERDICT_STYLE["insufficient-data"]);
  const pct = (n: number) => `${Math.round(n * 100)}%`;
  const ephemeral = calibration.persistent === false && calibration.samples > 0;
  const brierSeries = (trend ?? []).map((p) => p.brier);
  return (
    <div className={bare ? "" : "rounded-2xl glass p-4"}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[12px] font-medium text-muted">
          Calibration
          <InfoTip text="Whether the scores hold up: each tested path's predicted score against its real red-team/BAS outcome. The diagram plots predicted against observed per score range; each dot carries its 95% interval and the number of outcomes behind it." />
        </span>
        <div className="flex items-center gap-1.5">
          {ephemeral && (
            <span
              className="rounded-full bg-amber-500/15 px-2 py-0.5 text-[12px] font-medium text-amber-800"
              title="The verdict store is in-memory: this calibration dataset is lost on restart. Set VALIDATIONS_PATH to persist it for a real calibration program."
            >
              in-memory
            </span>
          )}
          <span className={`rounded-full px-2 py-0.5 text-[12px] font-medium ${v.cls}`}>{v.label}</span>
        </div>
      </div>
      <div className="grid items-center gap-6 sm:grid-cols-[minmax(0,17rem)_1fr]">
        <ReliabilityDiagram bins={calibration.bins} />
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-3">
            <Stat
              label="Brier score"
              value={calibration.brier.toFixed(3)}
              tip="Mean squared gap between predicted and actual, 0 to 1, lower is better. As a rough guide: under 0.10 is good, 0.10 to 0.25 fair, above 0.25 poor."
            />
            <Stat
              label="Calibration error"
              value={calibration.ece.toFixed(3)}
              tip="Expected calibration error: the average distance, per score range, between what was predicted and what happened. Under 0.10 is good, above 0.20 poor."
            />
            <Stat label="Outcomes" value={String(calibration.samples)} />
            <Stat label="Predicted on average" value={pct(calibration.meanPredicted)} />
            <Stat label="Happened" value={pct(calibration.observedRate)} />
            {calibration.recommendedScale != null && (
              <Stat
                label="Rescale factor"
                value={`× ${calibration.recommendedScale.toFixed(2)}`}
                tip="What multiplying every score by would make their average match the outcomes. Advisory and never applied: a single factor cannot fix scores that are wrong in different directions in different ranges."
              />
            )}
          </div>
          {brierSeries.length >= 2 && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-edge/60 pt-3">
              <span className="shrink-0 text-[12px] text-muted">Brier score over time</span>
              <div className="h-6 min-w-[6rem] max-w-[220px] flex-1">
                <Sparkline values={brierSeries} tone="rgb(var(--c-slate-600))" />
              </div>
              <span className="shrink-0 text-[12px] tabular-nums text-muted">
                {brierSeries[0].toFixed(3)} → {brierSeries[brierSeries.length - 1].toFixed(3)} over {brierSeries.length} passes
              </span>
            </div>
          )}
        </div>
      </div>

      <DiscriminationRow discrimination={calibration.discrimination} priorityDiscrimination={calibration.priorityDiscrimination} />

      {(calibration.diagnosis || (calibration.segments?.length ?? 0) > 0) && (
        <div className="mt-3 border-t border-edge/60 pt-3">
          {calibration.diagnosis && (
            // The diagnosis appears here and only here. It used to be printed twice, word for
            // word - once as "What to do" under the headline - and it is written for whoever
            // runs the calibration program, API field names included.
            <div className="flex items-start gap-2">
              <span className="mt-0.5 shrink-0 text-[12px] font-medium text-muted">Diagnosis</span>
              <span
                className={`flex-1 text-[12px] leading-snug ${calibration.diagnosis.startsWith("inverted") ? "text-flag" : "text-slate-700"}`}
              >
                {calibration.diagnosis}
              </span>
              <InfoTip text="The gate recommendation: recalibrate-first (a rescale fixes it), structural #6 (error on correlated/long paths), detection-axis #7 (paths get caught, so the score over-predicts), per-basis (one evidence source runs hot, another cold), low-resolution (inputs can't tell real from fake), or inverted-order (refuted paths outrank confirmed ones). Whatever it says about the ranking comes from the Score order line above, with its AUC." />
            </div>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {calibration.brierRecalibrated != null && (
              <span
                className="rounded-md bg-slate-500/10 px-1.5 py-0.5 text-[12px] tabular-nums text-slate-600"
                title="Brier after isotonic recalibration, measured on outcomes it was not fitted to - the best a rescale can reach. Near the raw Brier: recalibration won't help. Much lower: apply the map."
              >
                recalibrated Brier {calibration.brierRecalibrated.toFixed(3)}
              </span>
            )}
            {calibration.segments
              ?.filter((s) => s.samples >= 3)
              .map((s) => {
                const sv = VERDICT_STYLE[s.verdict] ?? VERDICT_STYLE["insufficient-data"];
                return (
                  <span
                    key={s.name}
                    className={`rounded-md px-1.5 py-0.5 text-[12px] font-medium ${sv.cls}`}
                    title={`${s.samples} samples · predicted ${pct(s.meanPredicted)} vs observed ${pct(s.observedRate)}`}
                  >
                    {s.name} · {sv.label}
                  </span>
                );
              })}
          </div>
        </div>
      )}
    </div>
  );
}
