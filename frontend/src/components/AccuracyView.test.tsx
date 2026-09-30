import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AccuracyView from "./AccuracyView";
import type { AttackPath, Calibration, Discrimination, ValidationMetrics } from "../api/client";
import { fetchValidations } from "../api/client";

vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  fetchValidations: vi.fn(),
}));

// The sentence at the top of Accuracy is the one a non-statistician reads and repeats. Each
// of these pins a claim it must only make when the evidence underneath supports it.

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

beforeEach(() => {
  vi.mocked(fetchValidations).mockResolvedValue({ validations: [], metrics: {} as ValidationMetrics, calibration: calibration({}), persistent: true });
});

describe("AccuracyView verdict sentence", () => {
  it("makes the per-score-range claim for a score calibrated in every range", () => {
    render(<AccuracyView calibration={calibration({ verdict: "well-calibrated" })} />);
    expect(screen.getByText(PER_BIN_CLAIM)).toBeInTheDocument();
  });

  // The regression: an uninformative score matched the base rate on average and this page
  // told the reader that 70% means 70%.
  it("does not claim 70% means 70% when only the average agrees", () => {
    render(<AccuracyView calibration={calibration({ verdict: "calibrated-on-average", ece: 0.21 })} />);
    expect(screen.queryByText(PER_BIN_CLAIM)).toBeNull();
    expect(screen.getByText(/only the average agrees/)).toBeInTheDocument();
  });

  // Without its own branch the verdict fell through to "too few to judge" - false at 500.
  it("does not call 500 outcomes too few to judge", () => {
    render(<AccuracyView calibration={calibration({ verdict: "calibrated-on-average", ece: 0.21 })} />);
    expect(screen.queryByText(/too few to judge/)).toBeNull();
  });

  // "The ranking is sound" is a claim about order, which calibration does not measure.
  it("only calls the ranking sound when discrimination has shown it", () => {
    const { unmount } = render(
      <AccuracyView calibration={calibration({ verdict: "overconfident", meanPredicted: 0.7, observedRate: 0.5 })} />,
    );
    expect(screen.queryByText(/ranking as sound/)).toBeNull();
    expect(screen.getByText(/whether the order itself holds up has not been shown/)).toBeInTheDocument();
    unmount();

    render(
      <AccuracyView
        calibration={calibration({ verdict: "overconfident", meanPredicted: 0.7, observedRate: 0.5, discrimination: discriminates })}
      />,
    );
    expect(screen.getByText(/ranking as sound/)).toBeInTheDocument();
  });
});

describe("AccuracyView headline", () => {
  // Fourteen outcomes used to headline "Underconfident" in 26px. Below the floor the
  // headline is the sample size; the direction sits beside the count that qualifies it.
  it("does not headline a verdict on too few outcomes", () => {
    render(<AccuracyView calibration={calibration({ samples: 14, verdict: "underconfident" })} />);
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent("Not enough outcomes yet");
    expect(screen.getByText(/14 of the 30 outcomes a verdict needs · leaning underconfident/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: /Outcomes recorded/ })).toHaveAttribute("aria-valuenow", "14");
  });

  it("headlines the verdict once there are enough", () => {
    render(<AccuracyView calibration={calibration({ samples: 500, verdict: "overconfident" })} />);
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent("Overconfident");
  });
});

describe("AccuracyView reading guide", () => {
  it("says what the verdict means for how to read a score", () => {
    const { unmount } = render(
      <AccuracyView calibration={calibration({ verdict: "overconfident", meanPredicted: 0.7, observedRate: 0.5 })} />,
    );
    expect(screen.getByText(/about 20 points too high/)).toBeInTheDocument();
    unmount();

    // Provisional: no adjustment, whatever the lean.
    render(<AccuracyView calibration={calibration({ samples: 8, verdict: "overconfident", meanPredicted: 0.7, observedRate: 0.5 })} />);
    expect(screen.getByText(/adjust nothing yet/)).toBeInTheDocument();
    expect(screen.queryByText(/points too high/)).toBeNull();
  });

  it("prints the diagnosis once, inside the details, which start closed", () => {
    // It was printed twice, word for word, and under the headline it named an API field.
    const { container } = render(
      <AccuracyView calibration={calibration({ diagnosis: "recalibrate-first: apply the recalibrationMap" })} />,
    );
    // The exact sentence: the diagnosis tip also lists the diagnosis names in the abstract.
    const matches = screen.getAllByText("recalibrate-first: apply the recalibrationMap");
    expect(matches).toHaveLength(1);
    const details = container.querySelector("details")!;
    expect(details).not.toHaveAttribute("open");
    expect(details).toContainElement(matches[0]);
  });
});

describe("AccuracyView evidence register", () => {
  const route: AttackPath = {
    id: "ap-1",
    score: 0.55,
    runtimeConfirmed: false,
    nodes: [
      { id: "lb", label: "LoadBalancer", name: "edge-alb", properties: {} },
      { id: "role", label: "IAM_Role", name: "payments-admin", properties: {} },
    ],
    steps: [],
    remediations: [],
    detections: [],
  };
  const validation: ValidationMetrics = {
    confirmed: 1, refuted: 0, partial: 0, missed: 1, tested: 1, precision: 1, recall: 0.5,
  } as ValidationMetrics;

  it("lists the outcomes the verdict rests on, naming the route each was recorded on", async () => {
    vi.mocked(fetchValidations).mockResolvedValue({
      validations: [
        { id: "v1", outcome: "confirmed", source: "caldera-bas", path_id: "ap-1", tested_at: "2026-09-01T10:00:00Z" },
        { id: "v2", outcome: "missed", source: "red-team", route: "Okta → SaaS → data export", tested_at: "2026-09-02T10:00:00Z" },
      ] as never,
      metrics: validation,
      calibration: calibration({}),
      persistent: true,
    });
    const onOpenPath = vi.fn();
    render(<AccuracyView calibration={calibration({})} validation={validation} paths={[route]} onOpenPath={onOpenPath} />);
    const register = (await screen.findByText("Recorded outcomes, newest first")).parentElement!;
    const rows = within(register).getAllByRole("listitem");
    // Newest first: the missed route, then the proven one.
    expect(rows[0]).toHaveTextContent("Missed");
    expect(rows[0]).toHaveTextContent("Okta → SaaS → data export");
    expect(rows[1]).toHaveTextContent("Proven");
    within(rows[1]).getByRole("button", { name: "edge-alb → payments-admin" }).click();
    expect(onOpenPath).toHaveBeenCalledWith("ap-1");
  });
});

describe("AccuracyView before the first outcome", () => {
  const noData = calibration({ hasData: false, samples: 0, verdict: "insufficient-data" });
  function route(id: string, score: number, low: number, high: number, basis = "heuristic"): AttackPath {
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
      steps: [{ edgeType: "EXPOSES", from: "a", to: "b", probability: score, weightBasis: basis }],
      remediations: [],
      detections: [],
    };
  }
  const paths = [
    route("ap-a", 0.9, 0.7, 0.99),
    route("ap-b", 0.85, 0.6, 0.99, "runtime"),
    route("ap-c", 0.5, 0.3, 0.8),
    route("ap-d", 0.3, 0.2, 0.5),
  ];

  // The page had a headline and nothing under it. What exists before any outcome is the
  // prediction side of every calibration point, so that is what it shows - and no more.
  it("shows every open route's prediction and interval, and draws no observed side", () => {
    render(<AccuracyView calibration={noData} paths={paths} onOpenPath={vi.fn()} />);
    expect(screen.getByText("The predictions waiting for an outcome")).toBeInTheDocument();
    expect(screen.getByText(/4 routes, predicted between 30% and 90%/)).toBeInTheDocument();
    expect(screen.getByText(/3 rest on estimates alone; 1 carries observed evidence/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "ap-a-entry → ap-a-target" })).toBeInTheDocument();
    expect(screen.getByText(/90% interval 70% to 99%/)).toBeInTheDocument();
    // No reliability diagram and no verdict: nothing has been observed.
    expect(screen.queryByRole("img", { name: /Reliability diagram/ })).toBeNull();
    expect(screen.queryByText("Calibration details")).toBeNull();
  });

  it("marks one route per score band to test first, the widest interval in each", () => {
    render(<AccuracyView calibration={noData} paths={paths} onOpenPath={vi.fn()} />);
    const picked = screen.getAllByText("test first").map((chip) => chip.closest("li")!.textContent);
    // Top band: ap-a (0.29 wide) loses to ap-b (0.39 wide); ap-c and ap-d are alone in theirs.
    expect(picked).toHaveLength(3);
    expect(picked.some((t) => t!.includes("ap-b-entry"))).toBe(true);
    expect(picked.some((t) => t!.includes("ap-a-entry"))).toBe(false);
  });

  it("opens the route a row names", () => {
    const onOpenPath = vi.fn();
    render(<AccuracyView calibration={noData} paths={paths} onOpenPath={onOpenPath} />);
    screen.getByRole("button", { name: "ap-c-entry → ap-c-target" }).click();
    expect(onOpenPath).toHaveBeenCalledWith("ap-c");
  });

  it("gives way to the measured page once outcomes exist", () => {
    render(<AccuracyView calibration={calibration({ samples: 40 })} paths={paths} />);
    expect(screen.queryByText("The predictions waiting for an outcome")).toBeNull();
  });
});
