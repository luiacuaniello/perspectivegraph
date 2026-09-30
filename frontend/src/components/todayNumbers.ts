import type { RiskSimulation } from "../api/client";

// shareRound turns fractions into whole percentages that add up to the rounded total.
//
// Rounded one by one, three fixes cutting 30.7%, 19.7% and 10.6% of the risk read "31%",
// "20%" and "11%" beside a sentence saying they cut 61% together - a sum anyone checks in
// their head, and the first number on the page that does not add up. The largest-remainder
// method hands the leftover points to the shares that lost the most in rounding, so the
// parts always sum to the whole the page prints.
export function shareRound(fractions: number[]): number[] {
  const exact = fractions.map((f) => f * 100);
  const floors = exact.map(Math.floor);
  const total = Math.round(exact.reduce((a, v) => a + v, 0));
  let left = total - floors.reduce((a, v) => a + v, 0);
  const order = exact
    .map((v, i) => ({ i, rem: v - Math.floor(v) }))
    .sort((a, b) => b.rem - a.rem || a.i - b.i);
  const out = floors.slice();
  for (const { i } of order) {
    if (left <= 0) break;
    out[i] += 1;
    left -= 1;
  }
  return out;
}

// riskBandNote says how firm the overall compromise estimate is. It used to have a section
// of its own on the Accuracy page, away from any risk number; it now explains the risk
// figure on Today, beside the number it qualifies.
export function riskBandNote(risk: RiskSimulation): string {
  const pct = (v: number) => `${Math.round(v * 100)}%`;
  if (risk.anyCompromiseProbability >= 0.99) {
    // Pinned at the top, "between 100% and 100%" read like a bug. It is saturation.
    return `The chance that at least one sensitive asset falls is saturated at ${pct(
      risk.anyCompromiseProbability,
    )}: with this many open routes some asset falls in almost every simulated attack, so that number cannot tell bad from worse, and resampling the evidence cannot move it. Cut routes and it starts carrying information again; until then the per-asset figures are the ones that move.`;
  }
  const width = risk.sensitivityHigh - risk.sensitivityLow;
  const band = `The chance that at least one sensitive asset falls is ${pct(risk.anyCompromiseProbability)}; resampling every edge probability from its evidence puts it between ${pct(
    risk.sensitivityLow,
  )} and ${pct(risk.sensitivityHigh)}.`;
  return width < 0.05
    ? `${band} That band is tight: the estimate is driven by evidence rather than guesses.`
    : `${band} That band is wide: treat the number qualitatively until more of its edges are evidence-backed.`;
}
