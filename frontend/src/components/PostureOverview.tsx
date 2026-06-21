import { humanDuration, type History, type Posture, type RiskSimulation, type ValidationMetrics } from "../api/client";
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
    <div className={`rounded-xl border border-edge bg-panel shadow-card p-4 transition hover:shadow-lift ${ring}`}>
      <div className="flex items-center gap-1.5">
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted">{label}</span>
        {tip && <InfoTip text={tip} />}
      </div>
      <div className={`mt-1.5 text-3xl font-bold tabular-nums tracking-tight ${accent}`}>{value}</div>
      <div className="mt-1 text-[11px] text-muted">{hint}</div>
    </div>
  );
}

export default function PostureOverview({
  posture,
  risk,
  history,
  validation,
}: {
  posture: Posture;
  risk?: RiskSimulation;
  history?: History;
  validation?: ValidationMetrics;
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
        tip="Active routes an attacker could walk from an internet-exposed asset to a crown jewel — excluding paths an analyst has triaged off the board (accept-risk / false-positive / mitigating-control / duplicate). Zero is the goal."
      />
      {pct !== null && (
        <Card
          label="Account compromise"
          value={`${pct}%`}
          accent={pct >= 50 ? "text-red-600" : pct > 0 ? "text-amber-600" : "text-emerald-600"}
          ring={pct >= 50 ? "shadow-[inset_0_1px_0_0_rgba(220,38,38,0.3)]" : ""}
          hint={`modeled ${Math.round(risk!.sensitivityLow * 100)}–${Math.round(risk!.sensitivityHigh * 100)}% · ~${risk!.expectedCompromised.toFixed(1)} jewels fall`}
          tip="Probability at least one crown jewel is compromised (Monte Carlo over thousands of attacker attempts). The ‘modeled X–Y%’ range is a sensitivity band: the answer if the heuristic per-edge probabilities are off by ±30% — so treat it as a modeled estimate, not a measurement."
        />
      )}
      <Card
        label="Runtime-confirmed"
        value={posture.runtimeConfirmed}
        accent={posture.runtimeConfirmed > 0 ? "text-red-600" : "text-slate-500"}
        ring={posture.runtimeConfirmed > 0 ? "shadow-[inset_0_1px_0_0_rgba(220,38,38,0.3)]" : ""}
        hint="actively exploited"
        tip="Paths crossing an asset with a live runtime alert (Falco). These aren’t theoretical — something is exercising them right now. Triage first."
      />
      <Card
        label="KEV on paths"
        value={posture.kevOnPaths}
        accent={posture.kevOnPaths > 0 ? "text-red-600" : "text-slate-500"}
        ring={posture.kevOnPaths > 0 ? "shadow-[inset_0_1px_0_0_rgba(220,38,38,0.3)]" : ""}
        hint="exploited in the wild"
        tip="CVEs on a path that are in CISA’s Known Exploited Vulnerabilities catalog — confirmed exploited in the wild, not just scored as risky."
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
          value={history.mttrSeconds != null ? humanDuration(history.mttrSeconds) : "—"}
          accent={history.mttrSeconds != null ? "text-slate-700" : "text-slate-400"}
          ring=""
          hint={history.resolvedPaths > 0 ? `over ${history.resolvedPaths} resolved` : "no resolutions yet"}
          tip="Mean time-to-remediate: the average time a critical path stayed open before it stopped appearing (was fixed or its asset went away). Tracked over the analysis history — the accountability metric a point-in-time scan can't give you."
        />
      )}
      {validation && (
        <Card
          label="Validation"
          value={vp != null ? `${vp}%` : "—"}
          accent={vp == null ? "text-slate-400" : vp >= 70 ? "text-emerald-600" : vp >= 40 ? "text-amber-600" : "text-red-600"}
          ring=""
          hint={
            validation.tested > 0
              ? `precision · ${validation.confirmed}/${validation.tested} real${validation.missed > 0 ? ` · ${validation.missed} missed` : ""}`
              : "no red-team/BAS verdicts yet"
          }
          tip="Red-team/BAS precision over the TESTED subset = confirmed ÷ (confirmed + refuted): of the paths the engine surfaced and someone actually tested, how many were real. Not a global claim — evidence that the engine is grounded, not just modeled. Record verdicts on a path or POST to /validations."
        />
      )}
      <Card
        label="Assets & findings"
        value={posture.nodes}
        accent="text-accent"
        ring=""
        hint="graph nodes"
        tip="Every asset, identity and finding correlated into the graph — VMs, containers, images, CVEs, IAM roles, buckets…"
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

      {trend.length >= 2 && (
        <div className="rounded-xl border border-edge bg-panel shadow-card p-4">
          <div className="mb-2 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              Exposure trend
              <InfoTip text="Critical paths and account-compromise probability over the analysis history. Security is managed on trends, not snapshots — a rising line is a regression to chase, a falling one is progress." />
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
    </div>
  );
}
