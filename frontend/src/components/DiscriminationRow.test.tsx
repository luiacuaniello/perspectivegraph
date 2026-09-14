import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DiscriminationRow } from "./DiscriminationRow";
import type { Discrimination } from "../api/client";

// The row is where the ranking is either shown to have been graded or shown not to have
// been. These pin the three ways it could mislead: a figure printed where none is defined,
// an ungraded AUC drawn like a result, and a missing Priority presented as a zero.

const judged: Discrimination = {
  positives: 14, negatives: 12, auc: 0.83, aucLow: 0.67, aucHigh: 0.99, verdict: "discriminates", hasData: true,
};

describe("DiscriminationRow", () => {
  it("prints the AUC, its interval and the verdict once the order has been graded", () => {
    render(<DiscriminationRow discrimination={judged} priorityDiscrimination={judged} />);
    expect(screen.getByTestId("Score order-auc")).toHaveTextContent("AUC 0.83 [0.67–0.99]");
    expect(screen.getAllByText("discriminates")).toHaveLength(2);
  });

  // Undefined is not zero. A dashboard that printed "AUC 0.00" here would be reporting a
  // perfectly inverted order that nobody measured.
  it("prints no figure when the AUC is undefined", () => {
    const undefinedAUC: Discrimination = { positives: 3, negatives: 0, verdict: "insufficient-data", hasData: false };
    render(<DiscriminationRow discrimination={undefinedAUC} priorityDiscrimination={null} />);
    // By test id, not by text: the explanatory tooltip legitimately contains the word AUC.
    expect(screen.queryByTestId("Score order-auc")).toBeNull();
    expect(screen.getByText(/needs a confirmed and a refuted verdict/)).toBeInTheDocument();
  });

  it("says the triage order is ungraded when no verdict recorded a Priority", () => {
    render(<DiscriminationRow discrimination={judged} priorityDiscrimination={null} />);
    expect(screen.queryByTestId("Triage order-auc")).toBeNull();
    expect(screen.getByText(/no verdict has recorded the Priority/)).toBeInTheDocument();
  });

  // 1.00 from one confirmed and one refuted verdict is the rank of two points. It is shown
  // - hiding it would be its own dishonesty - but muted, and labelled insufficient.
  it("mutes an AUC that is below the floor rather than drawing it like a result", () => {
    const thin: Discrimination = {
      positives: 1, negatives: 1, auc: 1, aucLow: 0.5, aucHigh: 1, verdict: "insufficient-data", hasData: true,
    };
    render(<DiscriminationRow discrimination={thin} priorityDiscrimination={null} />);
    const fig = screen.getByTestId("Score order-auc");
    expect(fig).toHaveTextContent("AUC 1.00");
    expect(fig.className).toContain("text-slate-400");
    expect(screen.getByText("insufficient data")).toBeInTheDocument();
  });
});
