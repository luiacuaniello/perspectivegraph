import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import AttackPathDetail from "./AttackPathDetail";
import type { AttackPath } from "../api/client";

// The detail panel is where the engine's honesty layers become a claim a human
// reads: the headline exploit score, the epistemic credible interval, and the
// correlation ceiling. Each is shown only when it carries information - a rule
// that is easy to break silently, since a wrong threshold still renders fine.
// These tests pin the display contract rather than the markup.

const base: AttackPath = {
  id: "ap-lb-role",
  score: 0.5,
  runtimeConfirmed: false,
  nodes: [
    { id: "lb", label: "LoadBalancer", name: "edge-lb", properties: {} },
    { id: "role", label: "IAM_Role", name: "admin-role", properties: {} },
  ],
  steps: [
    { edgeType: "EXPOSES", from: "lb", to: "role", probability: 0.5 },
  ],
  remediations: [],
  detections: [],
};

const path = (over: Partial<AttackPath>): AttackPath => ({ ...base, ...over });

describe("AttackPathDetail probability display", () => {
  it("headlines the exploit score as a whole percentage", () => {
    render(<AttackPathDetail path={path({ score: 0.5 })} />);
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.getByText(/exploit score/)).toBeInTheDocument();
  });

  it("shows the 90% credible interval when the band is wide enough to inform", () => {
    render(<AttackPathDetail path={path({ scoreCiLow: 0.38, scoreCiHigh: 0.71, confidenceLabel: "low" })} />);
    // A wide band is the whole point of the epistemic layer: surface it.
    expect(screen.getByText(/90% CI 38-71%/)).toBeInTheDocument();
  });

  it("suppresses a degenerate credible interval and falls back to the confidence label", () => {
    // A band narrower than 2 points is noise, not information: showing
    // "90% CI 50-51%" would imply precision the model does not have.
    render(<AttackPathDetail path={path({ scoreCiLow: 0.5, scoreCiHigh: 0.51, confidenceLabel: "high" })} />);
    expect(screen.queryByText(/90% CI/)).not.toBeInTheDocument();
    expect(screen.getByText("high confidence")).toBeInTheDocument();
  });

  it("shows the correlation ceiling only when hops actually share a basis", () => {
    // Same numbers, but without correlatedHops the ceiling is theoretical and
    // must stay hidden - otherwise every path grows a scary second number.
    render(<AttackPathDetail path={path({ score: 0.5, scoreUpperBound: 0.9, correlatedHops: false })} />);
    expect(screen.queryByText(/if correlated/)).not.toBeInTheDocument();
  });

  it("shows the correlation ceiling when hops are correlated and the gap is material", () => {
    render(<AttackPathDetail path={path({ score: 0.5, scoreUpperBound: 0.9, correlatedHops: true })} />);
    expect(screen.getByText(/up to 90% if correlated/)).toBeInTheDocument();
  });

  it("hides the correlation ceiling when the gap is negligible", () => {
    // correlatedHops is true, but a 2-point gap says the independence assumption
    // is barely doing any work - reporting it would be noise.
    render(<AttackPathDetail path={path({ score: 0.5, scoreUpperBound: 0.52, correlatedHops: true })} />);
    expect(screen.queryByText(/if correlated/)).not.toBeInTheDocument();
  });

  it("renders the per-profile breakdown with the blended mixture", () => {
    render(
      <AttackPathDetail
        path={path({
          profileScores: [
            { profile: "commodity", prior: 0.5, score: 0.12 },
            { profile: "apt", prior: 0.15, score: 0.72 },
          ],
          mixtureScore: 0.28,
        })}
      />,
    );
    expect(screen.getByText("Commodity")).toBeInTheDocument();
    expect(screen.getByText("12%")).toBeInTheDocument();
    // "apt" is upper-cased as an acronym, not title-cased.
    expect(screen.getByText("APT")).toBeInTheDocument();
    expect(screen.getByText("72%")).toBeInTheDocument();
    expect(screen.getByText(/blended 28%/)).toBeInTheDocument();
  });

  it("stays coherent when the attacker-marginal exceeds the correlation ceiling", () => {
    // Documented model interaction: scoreUpperBound is the Fréchet ceiling for a
    // FIXED attacker, while mixtureScore marginalizes over attacker capability -
    // a different axis. Under APT-heavy ATTACKER_PROFILE_PRIORS the blended value
    // can legitimately exceed the ceiling, so the two must not be read as one
    // scale. This pins that both are still rendered (no crash, no suppression);
    // if the UI later reconciles them, this test is the place to state the rule.
    render(
      <AttackPathDetail
        path={path({
          score: 0.3,
          scoreUpperBound: 0.5,
          correlatedHops: true,
          mixtureScore: 0.65,
          profileScores: [{ profile: "apt", prior: 0.9, score: 0.7 }],
        })}
      />,
    );
    expect(screen.getByText(/up to 50% if correlated/)).toBeInTheDocument();
    expect(screen.getByText(/blended 65%/)).toBeInTheDocument();
  });

  it("omits the profile row entirely when the backend sends no breakdown", () => {
    render(<AttackPathDetail path={path({ profileScores: null, mixtureScore: null })} />);
    expect(screen.queryByText(/by attacker profile/)).not.toBeInTheDocument();
    expect(screen.queryByText(/blended/)).not.toBeInTheDocument();
  });

  it("flags a runtime-confirmed path as actively exploited", () => {
    render(<AttackPathDetail path={path({ runtimeConfirmed: true })} />);
    expect(screen.getByText("ACTIVELY EXPLOITED")).toBeInTheDocument();
  });
});
