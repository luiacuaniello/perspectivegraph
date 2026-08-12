import { type Calibration, type CalibrationTrendPoint } from "../api/client";
import InfoTip from "./InfoTip";

// Sparkline draws a tiny trend line for a numeric series, normalized to its own
// range so the shape (up/down) reads at a glance even when values are close.
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
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-full w-full">
      <polyline points={pts} fill="none" stroke={tone} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// Maps a calibration verdict to its badge styling - the honest read at a glance:
// green when scores match reality, red/amber when they don't.
const VERDICT_STYLE: Record<string, { label: string; cls: string }> = {
  "well-calibrated": { label: "well-calibrated", cls: "bg-emerald-500/15 text-emerald-700" },
  overconfident: { label: "overconfident", cls: "bg-red-500/15 text-flag" },
  underconfident: { label: "underconfident", cls: "bg-amber-500/15 text-amber-700" },
  "insufficient-data": { label: "insufficient data", cls: "bg-slate-400/15 text-slate-500" },
};

// ReliabilityDiagram plots predicted (x) against observed (y) per bin over the
// unit square, with the y=x diagonal as "perfect calibration". Dots that sit above
// the line are underconfident, below are overconfident; dot size scales with how
// many verdicts back the bin. This is the picture a forecaster is judged by.
//
// Sized h-auto/w-full so the viewBox aspect sets the height and the drawing fills its
// box. At the previous fixed h-44 the 200x190 artwork letterboxed to 185px inside a
// 549px column: two thirds of the space given to the panel's best evidence was empty.
function ReliabilityDiagram({ bins }: { bins: Calibration["bins"] }) {
  const L = 30, R = 192, T = 8, B = 170; // plot box inside a 200x190 viewBox
  const x = (p: number) => L + p * (R - L);
  const y = (o: number) => B - o * (B - T);
  const populated = bins.filter((b) => b.count > 0);
  const maxCount = Math.max(1, ...populated.map((b) => b.count));
  return (
    <svg viewBox="0 0 200 190" className="h-auto w-full" role="img" aria-label="Reliability diagram">
      {/* plot frame + the perfect-calibration diagonal */}
      <rect x={L} y={T} width={R - L} height={B - T} fill="none" stroke="rgb(var(--c-edge))" strokeWidth={1} rx={4} />
      <line x1={x(0)} y1={y(0)} x2={x(1)} y2={y(1)} stroke="rgb(var(--c-muted) / 0.45)" strokeWidth={1} strokeDasharray="3 3" />
      {/* per-bin points: predicted vs observed */}
      {populated.map((b, i) => (
        <g key={i}>
          <line x1={x(b.meanPredicted)} y1={y(b.meanPredicted)} x2={x(b.meanPredicted)} y2={y(b.observedRate)} stroke="rgb(var(--c-accent) / 0.35)" strokeWidth={1} />
          <circle
            cx={x(b.meanPredicted)}
            cy={y(b.observedRate)}
            r={3 + (b.count / maxCount) * 4}
            fill="rgb(var(--c-accent) / 0.85)"
            stroke="rgb(var(--c-accent))"
            strokeWidth={1}
          />
        </g>
      ))}
      <text x={(L + R) / 2} y={188} textAnchor="middle" fontSize={9} fill="rgb(var(--c-muted))">predicted</text>
      <text x={10} y={(T + B) / 2} textAnchor="middle" fontSize={9} fill="rgb(var(--c-muted))" transform={`rotate(-90 10 ${(T + B) / 2})`}>observed</text>
    </svg>
  );
}

function Stat({ label, value, tone = "text-slate-700" }: { label: string; value: string; tone?: string }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted">{label}</div>
      <div className={`mt-0.5 text-[15px] font-semibold tabular-nums ${tone}`}>{value}</div>
    </div>
  );
}

// diagTone colours the gate diagnosis: green when calibrated, blue when a rescale
// fixes it, amber when a new model/axis is indicated.
function diagTone(d: string): string {
  if (d.startsWith("calibrated")) return "text-emerald-600";
  if (d.startsWith("recalibrate")) return "text-accent";
  return "text-amber-600";
}

// CalibrationPanel is the demo→production artifact: it shows whether the engine's
// predicted path scores actually match observed red-team/BAS outcomes, so an
// operator can defend "55%" as a probability rather than a label. Hidden entirely
// until at least one tested verdict carries a predicted score.
// Exported so the Trust view can host it as its own page: the calibration report
// is the product's differentiator, and it earns more than a card at the bottom of
// a scroll.
export function CalibrationPanel({ calibration, trend }: { calibration: Calibration; trend?: CalibrationTrendPoint[] }) {
  if (!calibration?.hasData) return null;
  const v = VERDICT_STYLE[calibration.verdict] ?? VERDICT_STYLE["insufficient-data"];
  const pct = (n: number) => `${Math.round(n * 100)}%`;
  const ephemeral = calibration.persistent === false && calibration.samples > 0;
  const brierSeries = (trend ?? []).map((p) => p.brier);
  return (
    <div className="rounded-2xl glass p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-medium text-muted">
          Calibration
          <InfoTip text="Whether the scores hold up: each tested path's predicted score vs its real red-team/BAS outcome. Brier and ECE are the error (lower is better); the diagram plots predicted vs observed." />
        </span>
        <div className="flex items-center gap-1.5">
          {ephemeral && (
            <span
              className="rounded-full bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold text-amber-700"
              title="The verdict store is in-memory: this calibration dataset is lost on restart. Set VALIDATIONS_PATH to persist it for a real calibration program."
            >
              in-memory
            </span>
          )}
          <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ${v.cls}`}>{v.label}</span>
        </div>
      </div>
      {/* The diagram gets a column sized to itself rather than half the panel, and the
          column beside it stacks the figures over the Brier trend. Six small stats do
          not fill 800px on their own - spread across it they drift apart, so the space
          carries the sparkline (previously a stray row above) instead of air. */}
      <div className="grid items-center gap-6 sm:grid-cols-[minmax(0,17rem)_1fr]">
        <ReliabilityDiagram bins={calibration.bins} />
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-3">
            <Stat label="Brier" value={calibration.brier.toFixed(3)} tone={calibration.brier <= 0.1 ? "text-emerald-600" : calibration.brier <= 0.25 ? "text-amber-600" : "text-flag"} />
            <Stat label="ECE" value={calibration.ece.toFixed(3)} tone={calibration.ece <= 0.1 ? "text-emerald-600" : calibration.ece <= 0.2 ? "text-amber-600" : "text-flag"} />
            <Stat label="Predicted" value={pct(calibration.meanPredicted)} />
            <Stat label="Observed" value={pct(calibration.observedRate)} tone="text-accent" />
            <Stat label="Samples" value={String(calibration.samples)} />
            {calibration.recommendedScale != null && (
              <Stat label="Suggested ×" value={calibration.recommendedScale.toFixed(2)} tone="text-slate-600" />
            )}
          </div>
          {brierSeries.length >= 2 && (
            <div className="flex items-center gap-3 border-t border-edge/60 pt-3">
              <span className="shrink-0 text-[10px] uppercase tracking-wide text-muted">Brier over time</span>
              <div className="h-6 max-w-[260px] flex-1">
                <Sparkline values={brierSeries} tone="rgb(var(--c-accent))" />
              </div>
              <span className="shrink-0 text-[10px] tabular-nums text-muted">
                {brierSeries.length} passes · now {calibration.brier.toFixed(3)}
              </span>
            </div>
          )}
        </div>
      </div>

      {(calibration.diagnosis || (calibration.segments?.length ?? 0) > 0 || calibration.detection) && (
        <div className="mt-3 border-t border-edge/60 pt-3">
          {calibration.diagnosis && (
            <div className="flex items-start gap-2">
              <span className="mt-0.5 text-[11px] font-medium text-muted">Diagnosis</span>
              <span className={`flex-1 text-[12px] leading-snug ${diagTone(calibration.diagnosis)}`}>{calibration.diagnosis}</span>
              <InfoTip text="The gate recommendation: recalibrate-first (a rescale fixes it), structural #6 (error on correlated/long paths), detection-axis #7 (paths get caught, so the score over-predicts), or low-resolution (inputs can't tell real from fake)." />
            </div>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {calibration.brierRecalibrated != null && (
              <span
                className="rounded-md bg-slate-500/10 px-1.5 py-0.5 text-[10px] tabular-nums text-slate-600"
                title="Brier after isotonic recalibration - the best a rescale can reach. Near the raw Brier: recalibration won't help. Much lower: apply the map."
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
                    className={`rounded-md px-1.5 py-0.5 text-[10px] font-medium ${sv.cls}`}
                    title={`${s.samples} samples · predicted ${pct(s.meanPredicted)} vs observed ${pct(s.observedRate)}`}
                  >
                    {s.name} · {sv.label}
                  </span>
                );
              })}
            {/* The detection statistic used to sit here, as one more grey chip beside
                "long-path · insufficient data". It is not the same kind of statement:
                those are notes about how much evidence a segment has, and this is a
                finding about the estate - of the routes that were confirmed exploitable,
                how many the detection stack caught. It needs no statistics to act on and
                it is the most alarming number on the page, so it now has its own row.
                See DetectionRow in TrustView. */}
          </div>
        </div>
      )}
    </div>
  );
}
