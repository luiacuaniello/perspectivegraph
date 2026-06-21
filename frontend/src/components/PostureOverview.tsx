import type { Posture } from "../api/client";

function Card({ label, value, accent }: { label: string; value: number | string; accent: string }) {
  return (
    <div className="flex-1 rounded-lg border border-edge bg-panel p-4">
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-3xl font-semibold ${accent}`}>{value}</div>
    </div>
  );
}

export default function PostureOverview({ posture }: { posture: Posture }) {
  return (
    <div className="flex gap-3">
      <Card
        label="Critical attack paths"
        value={posture.criticalPaths}
        accent={posture.criticalPaths > 0 ? "text-rose-400" : "text-emerald-400"}
      />
      <Card
        label="⚡ Runtime-confirmed"
        value={posture.runtimeConfirmed}
        accent={posture.runtimeConfirmed > 0 ? "text-rose-400" : "text-slate-400"}
      />
      <Card
        label="Policy violations"
        value={posture.policyViolations}
        accent={posture.policyViolations > 0 ? "text-amber-400" : "text-emerald-400"}
      />
      <Card label="Assets & findings" value={posture.nodes} accent="text-sky-300" />
      <Card label="Relationships" value={posture.edges} accent="text-teal-300" />
    </div>
  );
}
