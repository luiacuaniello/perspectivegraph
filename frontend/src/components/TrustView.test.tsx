import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import TrustView from "./TrustView";
import type { Calibration, Discrimination } from "../api/client";

// The sentence at the top of Trust is the one a non-statistician reads and repeats. Each of
// these pins a claim it must only make when the evidence underneath supports it.

function calibration(over: Partial<Calibration>): Calibration {
  return {
    samples: 500,
    brier: 0.2,
    logLoss: 0.6,
    ece: 0.04,
    meanPredicted: 0.5,
    observedRate: 0.5,
    verdict: "well-calibrated",
    hasData: true,
    bins: [],
    ...over,
  };
}

const PER_BIN_CLAIM = /roughly 70% is what happens/;
const discriminates: Discrimination = {
  positives: 150, negatives: 350, auc: 0.87, aucLow: 0.84, aucHigh: 0.91, verdict: "discriminates", hasData: true,
};

describe("TrustView verdict sentence", () => {
  it("makes the per-score-range claim for a score calibrated in every range", () => {
    render(<TrustView calibration={calibration({ verdict: "well-calibrated" })} />);
    expect(screen.getByText(PER_BIN_CLAIM)).toBeInTheDocument();
  });

  // The regression: an uninformative score matched the base rate on average and this page
  // told the reader that 70% means 70%.
  it("does not claim 70% means 70% when only the average agrees", () => {
    render(<TrustView calibration={calibration({ verdict: "calibrated-on-average", ece: 0.21 })} />);
    expect(screen.queryByText(PER_BIN_CLAIM)).toBeNull();
    expect(screen.getByText(/only the average agrees/)).toBeInTheDocument();
  });

  // Without its own branch the verdict fell through to "too few to judge" - false at 500.
  it("does not call 500 outcomes too few to judge", () => {
    render(<TrustView calibration={calibration({ verdict: "calibrated-on-average", ece: 0.21 })} />);
    expect(screen.queryByText(/too few to judge/)).toBeNull();
  });

  // "The ranking is sound" is a claim about order, which calibration does not measure.
  it("only calls the ranking sound when discrimination has shown it", () => {
    const { unmount } = render(
      <TrustView calibration={calibration({ verdict: "overconfident", meanPredicted: 0.7, observedRate: 0.5 })} />,
    );
    expect(screen.queryByText(/ranking as sound/)).toBeNull();
    expect(screen.getByText(/whether the order itself holds up has not been shown/)).toBeInTheDocument();
    unmount();

    render(
      <TrustView
        calibration={calibration({ verdict: "overconfident", meanPredicted: 0.7, observedRate: 0.5, discrimination: discriminates })}
      />,
    );
    expect(screen.getByText(/ranking as sound/)).toBeInTheDocument();
  });
});
