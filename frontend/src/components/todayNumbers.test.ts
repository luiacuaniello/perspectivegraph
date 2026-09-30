import { describe, expect, it } from "vitest";
import { riskBandNote, shareRound } from "./todayNumbers";
import type { RiskSimulation } from "../api/client";

describe("shareRound", () => {
  it("makes the parts add up to the whole the page prints", () => {
    // Rounded one by one these read 31 + 20 + 11 = 62 beside a total of 61.
    const parts = shareRound([0.307, 0.197, 0.106]);
    expect(parts.reduce((a, v) => a + v, 0)).toBe(61);
    expect(parts).toEqual([31, 20, 10]);
  });

  it("leaves shares that already add up alone", () => {
    expect(shareRound([0.3, 0.2, 0.1])).toEqual([30, 20, 10]);
    expect(shareRound([])).toEqual([]);
  });
});

describe("riskBandNote", () => {
  const risk = (over: Partial<RiskSimulation>) => ({ anyCompromiseProbability: 0.6, sensitivityLow: 0.5, sensitivityHigh: 0.7, ...over }) as RiskSimulation;

  // "between 100% and 100%" read like a bug.
  it("calls a saturated estimate saturated instead of printing a band with no width", () => {
    const note = riskBandNote(risk({ anyCompromiseProbability: 1, sensitivityLow: 1, sensitivityHigh: 1 }));
    expect(note).toMatch(/saturated at 100%/);
    expect(note).not.toMatch(/between/);
  });

  it("says whether the band is tight or wide", () => {
    expect(riskBandNote(risk({ sensitivityLow: 0.59, sensitivityHigh: 0.61 }))).toMatch(/tight/);
    expect(riskBandNote(risk({}))).toMatch(/between 50% and 70%.*wide/);
  });
});
