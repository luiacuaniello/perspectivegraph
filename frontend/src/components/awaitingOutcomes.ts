import type { AttackPath } from "../api/client";

// Before the first outcome, the Accuracy page has no verdict to give - and must not invent
// one. What it does have is the other half of every calibration point: the predictions. This
// module turns the open routes into that half, and picks the routes worth testing first.

// A hop's probability is evidence when something observed it (a KEV entry, an EPSS feed, a
// runtime alert) and an estimate when it was derived (CVSS, a severity, a heuristic). The same
// split the path detail draws.
const EVIDENCE_BASES = new Set(["kev", "epss", "runtime"]);

export interface Prediction {
  path: AttackPath;
  score: number;
  // The 90% credible interval around the score. A route without one (older engine, or open
  // access with no hops) is drawn as a point.
  low: number;
  high: number;
  // At least one hop rests on observed evidence rather than an estimate.
  evidenced: boolean;
}

export function predictions(paths: AttackPath[]): Prediction[] {
  return paths
    .map((path) => {
      const score = path.score;
      const low = Math.min(score, path.scoreCiLow ?? score);
      const high = Math.max(score, path.scoreCiHigh ?? score);
      const evidenced = path.steps.some((s) => EVIDENCE_BASES.has((s.weightBasis ?? "").toLowerCase()));
      return { path, score, low, high, evidenced };
    })
    .sort((a, b) => b.score - a.score || a.path.id.localeCompare(b.path.id));
}

// Five bands of twenty points; a score of exactly 1 belongs to the top one.
export const BANDS = 5;

export function bandOf(score: number): number {
  return Math.min(BANDS - 1, Math.max(0, Math.floor(score * BANDS)));
}

// testFirst picks one route from each score band: the one whose interval is widest, since an
// outcome moves a wide estimate the most. One per band, not the likeliest few, because a
// sample drawn only from the top of the ranking flatters the model - its confident
// predictions are the only ones ever checked. Spreading the tests is what lets calibration
// find where the scores are wrong.
//
// Open access is left out: a public bucket has no hop to test and no interval to narrow.
// Ties go to the lower confidence, then to the id, so the pick does not move between loads.
export function testFirst(preds: Prediction[]): Set<string> {
  const best = new Map<number, Prediction>();
  for (const p of preds) {
    if (p.path.directAccess) continue;
    const band = bandOf(p.score);
    const cur = best.get(band);
    if (!cur || wider(p, cur)) best.set(band, p);
  }
  return new Set([...best.values()].map((p) => p.path.id));
}

function wider(a: Prediction, b: Prediction): boolean {
  const wa = a.high - a.low;
  const wb = b.high - b.low;
  if (Math.abs(wa - wb) > 1e-9) return wa > wb;
  const ca = a.path.confidence ?? 1;
  const cb = b.path.confidence ?? 1;
  if (ca !== cb) return ca < cb;
  return a.path.id < b.path.id;
}
