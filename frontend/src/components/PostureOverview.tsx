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

interface CardProps {
  label: string;
  value: number | string;
  accent: string;
  ring: string;
  hint: string;
  tip?: string;
}

function Card({ label, value, accent, ring, hint, tip }: CardProps) {
  return (
    <div
      className={`group accent-topline relative overflow-hidden rounded-2xl glass p-4 transition duration-200 hover:-translate-y-0.5 hover:shadow-glow ${ring}`}
    >
      <div className="flex items-center gap-1.5">
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted">{label}</span>
        {tip && <InfoTip text={tip} />}
      </div>
      <div className={`mt-2.5 text-[34px] font-bold leading-none tabular-nums tracking-tight ${accent}`}>{value}</div>
      <div className="mt-1.5 text-[11px] text-muted">{hint}</div>
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
function CalibrationPanel({ calibration, trend }: { calibration: Calibration; trend?: CalibrationTrendPoint[] }) {
  if (!calibration?.hasData) return null;
  const v = VERDICT_STYLE[calibration.verdict] ?? VERDICT_STYLE["insufficient-data"];
  const pct = (n: number) => `${Math.round(n * 100)}%`;
  const ephemeral = calibration.persistent === false && calibration.samples > 0;
  const brierSeries = (trend ?? []).map((p) => p.brier);
  return (
    <div className="rounded-2xl glass p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
          Calibration
          <InfoTip text="Do the scores mean anything? Each tested path's predicted score is paired with its observed red-team/BAS outcome (confirmed/refuted) to check whether paths scored ~80% actually confirm ~80% of the time. Brier and ECE are error metrics (lower is better); the diagram plots predicted vs observed - points on the diagonal are perfectly calibrated. This is what turns a heuristic score into a defensible probability." />
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
            <Sparkline values={brierSeries} tone="rgb(56 200 255)" />
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
              <span className="mt-0.5 text-[10px] font-semibold uppercase tracking-widest text-muted">Diagnosis</span>
              <span className={`flex-1 text-[12px] leading-snug ${diagTone(calibration.diagnosis)}`}>{calibration.diagnosis}</span>
              <InfoTip text="The gate recommendation. recalibrate-first: a monotone rescale fixes it (apply the recalibration map). structural (#6): error concentrates on correlated/long paths, where the independence assumption breaks - consider a correlation-aware model. detection-axis (#7): reachable paths are routinely caught, so the score over-predicts undetected impact. low-resolution: even recalibration can't separate real from fake - revisit the inputs." />
            </div>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {calibration.brierRecalibrated != null && (
              <span
                className="rounded-md bg-slate-500/10 px-1.5 py-0.5 text-[10px] tabular-nums text-slate-600"
                title="Brier after isotonic recalibration - the floor a monotone rescale can reach. Close to the raw Brier means recalibration won't help; much lower means apply the recalibration map."
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
  return (
    <div className="flex flex-col gap-3">
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
      <Card
        label="Critical paths"
        value={posture.activePaths}
        accent={posture.activePaths > 0 ? "text-red-600" : "text-emerald-600"}
        ring={posture.activePaths > 0 ? "shadow-[inset_0_1px_0_0_rgba(220,38,38,0.3)]" : ""}
        hint={
          posture.suppressedPaths > 0
            ? `internet → crown jewel · ${posture.suppressedPaths} suppressed`
            : "internet → crown jewel"
        }
        tip="Active routes an attacker could walk from an internet-exposed asset to a crown jewel - excluding paths an analyst has triaged off the board (accept-risk / false-positive / mitigating-control / duplicate). Zero is the goal."
      />
      {pct !== null && (
        <Card
          label="Account compromise"
          value={`${pct}%`}
          accent={pct >= 50 ? "text-red-600" : pct > 0 ? "text-amber-600" : "text-emerald-600"}
          ring={pct >= 50 ? "shadow-[inset_0_1px_0_0_rgba(220,38,38,0.3)]" : ""}
          hint={`modeled ${Math.round(risk!.sensitivityLow * 100)}–${Math.round(risk!.sensitivityHigh * 100)}% · ~${risk!.expectedCompromised.toFixed(1)} jewels fall`}
          tip="Probability at least one crown jewel is compromised (Monte Carlo over thousands of attacker attempts). This number samples edges independently; the ‘modeled X–Y%’ range is a credible band from resampling each edge from its Beta posterior (how much the heuristic inputs move it). See ‘by attacker profile’ below for the correlation-aware view. A modeled estimate, not a measurement."
        />
      )}
      <Card
        label="Runtime-confirmed"
        value={posture.runtimeConfirmed}
        accent={posture.runtimeConfirmed > 0 ? "text-red-600" : "text-slate-500"}
        ring={posture.runtimeConfirmed > 0 ? "shadow-[inset_0_1px_0_0_rgba(220,38,38,0.3)]" : ""}
        hint="actively exploited"
        tip="Paths crossing an asset with a live runtime alert (Falco). These aren’t theoretical - something is exercising them right now. Triage first."
      />
      <Card
        label="KEV on paths"
        value={posture.kevOnPaths}
        accent={posture.kevOnPaths > 0 ? "text-red-600" : "text-slate-500"}
        ring={posture.kevOnPaths > 0 ? "shadow-[inset_0_1px_0_0_rgba(220,38,38,0.3)]" : ""}
        hint="exploited in the wild"
        tip="CVEs on a path that are in CISA’s Known Exploited Vulnerabilities catalog - confirmed exploited in the wild, not just scored as risky."
      />
      <Card
        label="Policy violations"
        value={posture.policyViolations}
        accent={posture.policyViolations > 0 ? "text-amber-600" : "text-emerald-600"}
        ring={posture.policyViolations > 0 ? "shadow-[inset_0_1px_0_0_rgba(245,158,11,0.25)]" : ""}
        hint="broken invariants"
        tip="Architectural rules the environment breaks (e.g. “the internet must never reach a crown jewel directly”). Guardrails for architects."
      />
      {history && (
        <Card
          label="MTTR"
          value={history.mttrSeconds != null ? humanDuration(history.mttrSeconds) : "-"}
          accent={history.mttrSeconds != null ? "text-slate-700" : "text-slate-400"}
          ring=""
          hint={history.resolvedPaths > 0 ? `over ${history.resolvedPaths} resolved` : "no resolutions yet"}
          tip="Mean time-to-remediate: the average time a critical path stayed open before it stopped appearing (was fixed or its asset went away). Tracked over the analysis history - the accountability metric a point-in-time scan can't give you."
        />
      )}
      {validation && (
        <Card
          label="Validation"
          value={vp != null ? `${vp}%` : "-"}
          accent={vp == null ? "text-slate-400" : vp >= 70 ? "text-emerald-600" : vp >= 40 ? "text-amber-600" : "text-red-600"}
          ring=""
          hint={
            validation.tested > 0
              ? `precision · ${validation.confirmed}/${validation.tested} real${validation.missed > 0 ? ` · ${validation.missed} missed` : ""}`
              : "no red-team/BAS verdicts yet"
          }
          tip="Red-team/BAS precision over the TESTED subset = confirmed ÷ (confirmed + refuted): of the paths the engine surfaced and someone actually tested, how many were real. Not a global claim - evidence that the engine is grounded, not just modeled. Record verdicts on a path or POST to /validations."
        />
      )}
      <Card
        label="Assets & findings"
        value={posture.nodes}
        accent="text-accent"
        ring=""
        hint="graph nodes"
        tip="Every asset, identity and finding correlated into the graph - VMs, containers, images, CVEs, IAM roles, buckets…"
      />
      <Card
        label="Relationships"
        value={posture.edges}
        accent="text-slate-600"
        ring=""
        hint="graph edges"
        tip="Directed connections between nodes (exposes, routes-to, can-escalate-to…). Attack paths are walks over these edges."
      />
    </div>

      {risk?.profileCompromise && risk.profileCompromise.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 rounded-2xl glass px-4 py-2.5">
          <span className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-widest text-muted">
            compromise by attacker profile
            <InfoTip text="P(any crown jewel compromised) marginalized over attacker capability - the correlation-aware headline Σ P(c)·R_c. The 'Account compromise' card above samples edges independently (the baseline); this reintroduces the same latent-capability correlation the per-path scores already reflect, broken down per profile." />
          </span>
          {risk.profileCompromise.map((p) => {
            const tone =
              p.profile === "apt"
                ? "border-red-300 bg-red-50 text-red-700 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-300"
                : p.profile === "criminal"
                  ? "border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-300"
                  : "border-edge bg-slate-500/10 text-slate-600";
            const label = p.profile === "apt" ? "APT" : p.profile.charAt(0).toUpperCase() + p.profile.slice(1);
            return (
              <span
                key={p.profile}
                className={`rounded-md border px-1.5 py-0.5 text-[11px] font-medium tabular-nums ${tone}`}
                title={`threat-model prior ${Math.round(p.prior * 100)}%`}
              >
                {label} {Math.round(p.probability * 100)}%
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
            <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              Exposure trend
              <InfoTip text="Critical paths and account-compromise probability over the analysis history. Security is managed on trends, not snapshots - a rising line is a regression to chase, a falling one is progress." />
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
