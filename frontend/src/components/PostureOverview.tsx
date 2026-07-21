import { humanDuration, type Calibration, type CalibrationTrendPoint, type History, type Posture, type RiskSimulation, type ValidationMetrics } from "../api/client";
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
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-8 w-full">
      <polyline points={pts} fill="none" stroke={tone} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

// StripStat is one secondary metric in the compact posture strip: a number and a
// sentence-case label, monochrome by default, red only when it flags live danger
// (a non-zero critical-path / runtime / KEV count) and amber for policy drift.
function StripStat({
  label,
  value,
  danger,
  warn,
}: {
  label: string;
  value: number | string;
  danger?: boolean;
  warn?: boolean;
}) {
  const tone = danger ? "text-red-600" : warn ? "text-amber-600" : "text-slate-900";
  return (
    <div className="min-w-0">
      <div className={`text-[19px] font-semibold leading-none tabular-nums ${tone}`}>{value}</div>
      <div className="mt-1.5 text-[11px] text-muted">{label}</div>
    </div>
  );
}

// Maps a calibration verdict to its badge styling - the honest read at a glance:
// green when scores match reality, red/amber when they don't.
const VERDICT_STYLE: Record<string, { label: string; cls: string }> = {
  "well-calibrated": { label: "well-calibrated", cls: "bg-emerald-500/15 text-emerald-700" },
  overconfident: { label: "overconfident", cls: "bg-red-500/15 text-red-700" },
  underconfident: { label: "underconfident", cls: "bg-amber-500/15 text-amber-700" },
  "insufficient-data": { label: "insufficient data", cls: "bg-slate-400/15 text-slate-500" },
};

// ReliabilityDiagram plots predicted (x) against observed (y) per bin over the
// unit square, with the y=x diagonal as "perfect calibration". Dots that sit above
// the line are underconfident, below are overconfident; dot size scales with how
// many verdicts back the bin. This is the picture a forecaster is judged by.
function ReliabilityDiagram({ bins }: { bins: Calibration["bins"] }) {
  const L = 30, R = 192, T = 8, B = 170; // plot box inside a 200x190 viewBox
  const x = (p: number) => L + p * (R - L);
  const y = (o: number) => B - o * (B - T);
  const populated = bins.filter((b) => b.count > 0);
  const maxCount = Math.max(1, ...populated.map((b) => b.count));
  return (
    <svg viewBox="0 0 200 190" className="h-44 w-full" role="img" aria-label="Reliability diagram">
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
      {brierSeries.length >= 2 && (
        <div className="mb-3 flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-wide text-muted">Brier over time</span>
          <div className="h-6 max-w-[180px] flex-1">
            <Sparkline values={brierSeries} tone="rgb(109 108 240)" />
          </div>
          <span className="text-[10px] tabular-nums text-muted">
            {brierSeries.length} samples · now {calibration.brier.toFixed(3)}
          </span>
        </div>
      )}
      <div className="grid items-center gap-3 sm:grid-cols-2">
        <ReliabilityDiagram bins={calibration.bins} />
        <div className="grid grid-cols-2 gap-3">
          <Stat label="Brier" value={calibration.brier.toFixed(3)} tone={calibration.brier <= 0.1 ? "text-emerald-600" : calibration.brier <= 0.25 ? "text-amber-600" : "text-red-600"} />
          <Stat label="ECE" value={calibration.ece.toFixed(3)} tone={calibration.ece <= 0.1 ? "text-emerald-600" : calibration.ece <= 0.2 ? "text-amber-600" : "text-red-600"} />
          <Stat label="Predicted" value={pct(calibration.meanPredicted)} />
          <Stat label="Observed" value={pct(calibration.observedRate)} tone="text-accent" />
          <Stat label="Samples" value={String(calibration.samples)} />
          {calibration.recommendedScale != null && (
            <Stat label="Suggested ×" value={calibration.recommendedScale.toFixed(2)} tone="text-slate-600" />
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
            {calibration.detection && (
              <span
                className="rounded-md bg-slate-500/10 px-1.5 py-0.5 text-[10px] tabular-nums text-slate-600"
                title="Of reachable (confirmed) paths carrying a detection report, how many were caught/blocked - the detection-axis (#7) evidence."
              >
                detection {calibration.detection.detected}/{calibration.detection.tested} caught
                {calibration.detection.highScoreTested > 0 ? ` · ${pct(calibration.detection.highScoreDetectionRate)} on high-score` : ""}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function PostureOverview({
  posture,
  risk,
  history,
  validation,
  calibration,
  calibrationTrend,
}: {
  posture: Posture;
  risk?: RiskSimulation;
  history?: History;
  validation?: ValidationMetrics;
  calibration?: Calibration;
  calibrationTrend?: CalibrationTrendPoint[];
}) {
  const pct = risk ? Math.round(risk.anyCompromiseProbability * 100) : null;
  const vp = validation?.precision != null ? Math.round(validation.precision * 100) : null;
  const trend = history?.trend ?? [];
  const verdict = calibration?.hasData ? (VERDICT_STYLE[calibration.verdict] ?? VERDICT_STYLE["insufficient-data"]) : null;
  const verdictDot =
    calibration?.verdict === "well-calibrated"
      ? "bg-emerald-500"
      : calibration?.verdict === "overconfident"
        ? "bg-red-500"
        : calibration?.verdict === "underconfident"
          ? "bg-amber-500"
          : "bg-slate-400";
  const reach = pct == null ? "" : pct >= 80 ? "near-certainty" : pct >= 40 ? "meaningful probability" : "low probability";
  return (
    <div className="flex flex-col gap-4">
      <section className="rounded-2xl glass p-6">
        <div className="flex items-center gap-1.5 text-[12px] text-muted">
          Account compromise
          <InfoTip text="P(at least one sensitive asset compromised) - Monte Carlo over thousands of attacker attempts. The modeled range is the credible band from per-edge evidence. An estimate, not a measurement." />
        </div>
        <div className="mt-1.5 flex flex-wrap items-baseline gap-x-4 gap-y-2">
          <span className={`text-[52px] font-semibold leading-none tabular-nums tracking-tight ${pct != null && pct >= 50 ? "text-red-600" : "text-slate-900"}`}>
            {pct != null ? `${pct}%` : "-"}
          </span>
          {verdict && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-edge px-2.5 py-1 text-[11px] text-muted">
              <span className={`h-1.5 w-1.5 rounded-full ${verdictDot}`} />
              model {verdict.label}
            </span>
          )}
        </div>
        {pct != null && (
          <>
            <p className="mt-3 max-w-[64ch] text-[13px] leading-relaxed text-slate-600">
              An attacker reaches at least one sensitive asset with {reach}; about {risk!.expectedCompromised.toFixed(1)} fall on average.
              {posture.runtimeConfirmed > 0 &&
                ` ${posture.runtimeConfirmed} route${posture.runtimeConfirmed === 1 ? "" : "s"} confirmed live in runtime.`}
            </p>
            <div className="mt-3.5 h-[3px] w-full overflow-hidden rounded-full bg-panel-2">
              <div className={`h-full rounded-full ${pct >= 50 ? "bg-red-500/70" : "bg-accent/70"}`} style={{ width: `${pct}%` }} />
            </div>
            <div className="mt-2 text-[11px] text-muted">
              modeled {Math.round(risk!.sensitivityLow * 100)} to {Math.round(risk!.sensitivityHigh * 100)}%
            </div>
          </>
        )}

        <div className="mt-6 grid grid-cols-2 gap-x-4 gap-y-4 border-t border-edge pt-5 sm:grid-cols-3 lg:grid-cols-5">
          <StripStat label="Critical paths" value={posture.activePaths} danger={posture.activePaths > 0} />
          <StripStat label="Runtime-confirmed" value={posture.runtimeConfirmed} danger={posture.runtimeConfirmed > 0} />
          <StripStat label="KEV on paths" value={posture.kevOnPaths} danger={posture.kevOnPaths > 0} />
          <StripStat label="Policy violations" value={posture.policyViolations} warn={posture.policyViolations > 0} />
          <StripStat label="Validated" value={vp != null ? `${vp}%` : "-"} />
        </div>
        <div className="mt-4 text-[11px] text-muted">
          {posture.nodes} assets &middot; {posture.edges} relationships
          {posture.suppressedPaths > 0 && ` · ${posture.suppressedPaths} suppressed`}
          {history?.mttrSeconds != null && ` · MTTR ${humanDuration(history.mttrSeconds)}`}
        </div>
      </section>

      {risk?.profileCompromise && risk.profileCompromise.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 rounded-2xl glass px-4 py-2.5">
          <span className="flex items-center gap-1 text-[11px] text-muted">
            Compromise by attacker profile
            <InfoTip text="P(any sensitive asset compromised), broken down per attacker profile - the correlation-aware counterpart to 'Account compromise', which samples edges independently." />
          </span>
          {risk.profileCompromise.map((p) => {
            const label = p.profile === "apt" ? "APT" : p.profile.charAt(0).toUpperCase() + p.profile.slice(1);
            return (
              <span
                key={p.profile}
                className="rounded-md border border-edge px-2 py-0.5 text-[11px] tabular-nums text-muted"
                title={`threat-model prior ${Math.round(p.prior * 100)}%`}
              >
                {label} <span className="font-medium text-slate-900">{Math.round(p.probability * 100)}%</span>
              </span>
            );
          })}
          {risk.mixtureCompromiseProbability != null && (
            <span
              className="text-[10px] tabular-nums text-muted"
              title="Threat-model-weighted average across profiles - the correlation-aware counterpart to the independent 'Account compromise' number."
            >
              blended {Math.round(risk.mixtureCompromiseProbability * 100)}%
            </span>
          )}
        </div>
      )}

      {trend.length >= 2 && (
        <div className="rounded-2xl glass p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-[11px] font-medium text-muted">
              Exposure trend
              <InfoTip text="Critical paths and account-compromise probability over time. Manage on trends, not snapshots: a rising line is a regression, a falling one is progress." />
            </span>
            <span className="text-[11px] text-slate-400">
              {trend.length} samples{history?.oldestOpenSince ? ` · oldest open ${new Date(history.oldestOpenSince).toLocaleDateString()}` : ""}
            </span>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <div className="text-[11px] text-slate-500">
                Critical paths · now <span className="font-semibold tabular-nums text-slate-700">{trend[trend.length - 1].criticalPaths}</span>
              </div>
              <Sparkline values={trend.map((p) => p.criticalPaths)} tone="rgb(220 38 38)" />
            </div>
            <div>
              <div className="text-[11px] text-slate-500">
                Account compromise · now <span className="font-semibold tabular-nums text-slate-700">{Math.round(trend[trend.length - 1].riskPct)}%</span>
              </div>
              <Sparkline values={trend.map((p) => p.riskPct)} tone="rgb(217 119 6)" />
            </div>
          </div>
        </div>
      )}

      {calibration && <CalibrationPanel calibration={calibration} trend={calibrationTrend} />}
    </div>
  );
}
