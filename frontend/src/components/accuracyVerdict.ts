import type { Calibration } from "../api/client";

// Below this many recorded outcomes a calibration verdict is a direction, not a finding.
//
// It is not a statistical threshold so much as an honesty one: at n=14 the 95% interval
// on an observed rate spans roughly 42%-90%, so an 11-point gap between predicted and
// observed sits comfortably inside the noise. The Accuracy page and the Today card both
// state the verdict, and both must say the same thing about it.
export const PROVISIONAL_BELOW = 30;

export function isProvisional(c?: Calibration): boolean {
  return !!c?.hasData && c.samples < PROVISIONAL_BELOW;
}

// meaningFor is the instruction the verdict implies, in the reader's terms: how to read a
// score today. It never names a statistic or an API field - those are in the details.
export function meaningFor(c?: Calibration): string {
  if (!c?.hasData) {
    return "read every score as an expert estimate: nothing has graded it yet. Record red-team or BAS outcomes against the routes and this page starts grading them.";
  }
  const gap = Math.round(Math.abs(c.meanPredicted - c.observedRate) * 100);
  if (isProvisional(c)) {
    const lean =
      c.verdict === "overconfident"
        ? " So far they lean high."
        : c.verdict === "underconfident"
          ? " So far they lean low."
          : c.verdict === "calibrated-on-average"
            ? " So far the average holds up, individual scores do not."
            : c.verdict === "well-calibrated"
              ? " So far they hold up."
              : "";
    return `adjust nothing yet. Use the scores to decide which routes to look at first, not as probabilities - ${c.samples} outcomes cannot say how far a score is off.${lean}`;
  }
  switch (c.verdict) {
    case "well-calibrated":
      return "read the scores as probabilities: a route at 70% turns out real about 70% of the time.";
    case "calibrated-on-average":
      return "use the scores to rank routes, not as probabilities: the average is right, but individual scores are not.";
    case "overconfident":
      return `read the probabilities as about ${gap} points too high.${
        c.discrimination?.verdict === "discriminates" ? " The order still holds: the routes at the top are the right ones to open first." : ""
      }`;
    case "underconfident":
      return `read the probabilities as about ${gap} points too low: attackers get further than the scores say.`;
    default:
      return "adjust nothing yet: there are too few outcomes to say how far the scores are off.";
  }
}
