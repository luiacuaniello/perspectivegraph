import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import PostureOverview from "./PostureOverview";
import type { Posture, RiskSimulation } from "../api/client";

const posture: Posture = {
  criticalPaths: 12,
  activePaths: 10,
  suppressedPaths: 2,
  runtimeConfirmed: 2,
  kevOnPaths: 1,
  policyViolations: 9,
  nodes: 33,
  edges: 27,
};

const risk: RiskSimulation = {
  iterations: 2000,
  anyCompromiseProbability: 0.999,
  anyCiLow: 0.997,
  anyCiHigh: 1,
  sensitivityLow: 0.82,
  sensitivityHigh: 1,
  expectedCompromised: 5.3,
  crownJewels: [],
};

describe("PostureOverview", () => {
  it("headlines active paths and notes how many are suppressed", () => {
    render(<PostureOverview posture={posture} />);
    expect(screen.getByText("Critical paths")).toBeInTheDocument();
    // The headline is the active count (suppressed paths are off the board).
    expect(screen.getByText("10")).toBeInTheDocument();
    expect(screen.getByText(/2 suppressed/)).toBeInTheDocument();
  });

  it("communicates Monte Carlo uncertainty via the sensitivity band, not a bare %", () => {
    render(<PostureOverview posture={posture} risk={risk} />);
    expect(screen.getByText("Account compromise")).toBeInTheDocument();
    // The honest secondary line must show the modeled band (82 to 100%), not just 100%.
    expect(screen.getByText(/modeled 82 to 100%/)).toBeInTheDocument();
  });
});
