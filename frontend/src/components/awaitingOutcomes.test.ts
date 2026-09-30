import { describe, expect, it } from "vitest";
import type { AttackPath } from "../api/client";
import { bandOf, predictions, testFirst } from "./awaitingOutcomes";

function route(id: string, score: number, low?: number, high?: number, over: Partial<AttackPath> = {}): AttackPath {
  return {
    id,
    score,
    scoreCiLow: low,
    scoreCiHigh: high,
    runtimeConfirmed: false,
    nodes: [
      { id: "a", label: "LoadBalancer", name: `${id}-entry`, properties: {} },
      { id: "b", label: "IAM_Role", name: `${id}-target`, properties: {} },
    ],
    steps: [{ edgeType: "EXPOSES", from: "a", to: "b", probability: score, weightBasis: "heuristic" }],
    remediations: [],
    detections: [],
    ...over,
  };
}

describe("predictions", () => {
  it("orders by score, highest first, and draws a route without an interval as a point", () => {
    const got = predictions([route("low", 0.3, 0.2, 0.5), route("high", 0.9), route("mid", 0.6, 0.4, 0.8)]);
    expect(got.map((p) => p.path.id)).toEqual(["high", "mid", "low"]);
    expect(got[0]).toMatchObject({ low: 0.9, high: 0.9 });
  });

  // The split the path detail draws: observed evidence (KEV, EPSS, runtime) against a
  // derived estimate (CVSS, severity, heuristic). One observed hop is enough.
  it("counts a route as evidenced when any hop was observed", () => {
    const observed = route("rt", 0.5, 0.4, 0.6, {
      steps: [
        { edgeType: "EXPOSES", from: "a", to: "b", probability: 0.9, weightBasis: "runtime" },
        { edgeType: "ASSUMES", from: "b", to: "c", probability: 0.5, weightBasis: "heuristic" },
      ],
    });
    const [a, b] = predictions([observed, route("est", 0.4, 0.3, 0.5)]);
    expect(a.evidenced).toBe(true);
    expect(b.evidenced).toBe(false);
  });
});

describe("testFirst", () => {
  it("puts a score of exactly 1 in the top band", () => {
    expect(bandOf(1)).toBe(4);
    expect(bandOf(0.8)).toBe(4);
    expect(bandOf(0.79)).toBe(3);
    expect(bandOf(0)).toBe(0);
  });

  // The whole point: not the likeliest few. A pick drawn only from the top of the ranking
  // would check the engine's confident predictions and nothing else.
  it("picks one route per score band, the one with the widest interval", () => {
    const picks = testFirst(
      predictions([
        route("top-narrow", 0.9, 0.85, 0.95),
        route("top-wide", 0.85, 0.6, 0.99),
        route("mid-narrow", 0.5, 0.45, 0.55),
        route("mid-wide", 0.55, 0.3, 0.8),
        route("bottom", 0.1, 0.05, 0.2),
      ]),
    );
    expect([...picks].sort()).toEqual(["bottom", "mid-wide", "top-wide"]);
  });

  it("leaves out open access, which has no hop to test", () => {
    const open = route("bucket", 1, undefined, undefined, { directAccess: true, steps: [] });
    expect(testFirst(predictions([open, route("role", 0.85, 0.7, 0.95)]))).toEqual(new Set(["role"]));
  });

  // A pick that moved between two loads of the same data would read as arbitrary.
  it("breaks a tie on the lower confidence, then on the id", () => {
    const a = route("a", 0.5, 0.4, 0.6, { confidence: 0.6 });
    const b = route("b", 0.5, 0.4, 0.6, { confidence: 0.35 });
    expect(testFirst(predictions([a, b]))).toEqual(new Set(["b"]));
    const c = route("c", 0.5, 0.4, 0.6);
    const d = route("d", 0.5, 0.4, 0.6);
    expect(testFirst(predictions([d, c]))).toEqual(new Set(["c"]));
  });
});
