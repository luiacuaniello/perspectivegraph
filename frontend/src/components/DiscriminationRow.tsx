import { type Discrimination } from "../api/client";
import InfoTip from "./InfoTip";

// DiscriminationRow answers the question the rest of the calibration panel does not:
// does the ORDER mean anything? Brier and the reliability diagram grade whether "0.8"
// happens 80% of the time; a score can pass that and still separate nothing, and the
// ranking - not the number - is what decides which path someone opens first.
//
// It lives in its own component so CalibrationPanel's own test (issue #97) stays the
// scoped task it was written as.

const STYLE: Record<string, { label: string; cls: string }> = {
  discriminates: { label: "discriminates", cls: "bg-emerald-500/15 text-emerald-700" },
  "indistinguishable-from-chance": { label: "not shown to beat chance", cls: "bg-amber-500/15 text-amber-700" },
  inverted: { label: "inverted", cls: "bg-red-500/15 text-flag" },
  "insufficient-data": { label: "insufficient data", cls: "bg-slate-400/15 text-slate-500" },
};

// A judged verdict earns full-strength figures. Below the per-class floor the AUC is
// still shown, but muted: 1.00 from one confirmed and one refuted verdict is the rank of
// two points, and printing it like a result would teach people to trust it.
const JUDGED = new Set(["discriminates", "indistinguishable-from-chance", "inverted"]);

function Line({ label, tip, d, emptyText }: { label: string; tip: string; d?: Discrimination | null; emptyText: string }) {
  const style = STYLE[d?.verdict ?? ""] ?? STYLE["insufficient-data"];
  const defined = !!d?.hasData && d.auc != null;
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="flex w-24 shrink-0 items-center gap-1 text-[12px] font-medium text-muted">
        {label}
        <InfoTip text={tip} />
      </span>
      {defined ? (
        <>
          <span
            data-testid={`${label}-auc`}
            className={`text-[12px] tabular-nums ${JUDGED.has(d.verdict) ? "text-slate-700" : "text-slate-500"}`}
            title={`${d.positives} confirmed · ${d.negatives} refuted · 95% interval ${d.aucLow?.toFixed(2)}–${d.aucHigh?.toFixed(2)}`}
          >
            AUC {d.auc!.toFixed(2)}{" "}
            <span className="text-muted">
              [{d.aucLow?.toFixed(2)}–{d.aucHigh?.toFixed(2)}]
            </span>
          </span>
          <span className={`rounded-md px-1.5 py-0.5 text-[12px] font-medium ${style.cls}`}>{style.label}</span>
        </>
      ) : (
        <span className="text-[12px] text-slate-500">{emptyText}</span>
      )}
    </div>
  );
}

export function DiscriminationRow({
  discrimination,
  priorityDiscrimination,
}: {
  discrimination?: Discrimination | null;
  priorityDiscrimination?: Discrimination | null;
}) {
  return (
    <div className="mt-3 flex flex-col gap-1.5 border-t border-edge/60 pt-3">
      <Line
        label="Score order"
        tip="Whether higher scores go to paths that turned out real. AUC: the chance a confirmed path outranks a refuted one - 0.5 is a coin, 1 is perfect. Separate from calibration: a score can be honest about 80% and still order nothing."
        d={discrimination}
        emptyText="not graded yet - needs a confirmed and a refuted verdict"
      />
      <Line
        label="Triage order"
        tip="Whether the Priority order you work down puts real paths first. Priority also weighs how sensitive the target is, so a refuted path to a crown jewel ranking high is partly by design."
        d={priorityDiscrimination}
        emptyText="not graded yet - no verdict has recorded the Priority it was given"
      />
    </div>
  );
}
