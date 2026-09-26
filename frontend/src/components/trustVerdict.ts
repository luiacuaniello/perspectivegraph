import type { Calibration } from "../api/client";

// Below this many recorded outcomes a calibration verdict is a direction, not a finding.
//
// It is not a statistical threshold so much as an honesty one: at n=14 the 95% interval
// on an observed rate spans roughly 42%-90%, so an 11-point gap between predicted and
// observed sits comfortably inside the noise. The Trust page and the Today card both
// state the verdict, and both must say the same thing about it.
export const PROVISIONAL_BELOW = 30;

export function isProvisional(c?: Calibration): boolean {
  return !!c?.hasData && c.samples < PROVISIONAL_BELOW;
}
