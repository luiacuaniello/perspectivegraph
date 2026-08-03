import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import TodayView from "./TodayView";
import type { AttackPath, Dashboard, Fix, RiskSimulation } from "../api/client";

// Today exists to answer "what do I do now". These tests pin the decisions that
// make it that, rather than another inventory: fixes lead, the headline numbers
// are ones that MOVE as work lands, and a runtime-confirmed route interrupts.

const posture: Dashboard["posture"] = {
  criticalPaths: 14,
  activePaths: 14,
  suppressedPaths: 0,
  runtimeConfirmed: 2,
  kevOnPaths: 0,
  policyViolations: 12,
  nodes: 44,
  edges: 40,
};

const risk: RiskSimulation = {
  iterations: 2000,
  anyCompromiseProbability: 1,
  anyCiLow: 1,
  anyCiHigh: 1,
  sensitivityLow: 1,
  sensitivityHigh: 1,
  expectedCompromised: 5.6,
  crownJewels: [
    { id: "a", name: "account-admin", label: "IAM_Role", compromiseProbability: 0.97, ciLow: 0.9, ciHigh: 1 },
    { id: "b", name: "customer-db", label: "Database", compromiseProbability: 0.81, ciLow: 0.7, ciHigh: 0.9 },
    { id: "c", name: "cold-storage", label: "Bucket", compromiseProbability: 0, ciLow: 0, ciHigh: 0 },
  ],
};

const fix = (title: string, coveragePct: number, pathCount: number): Fix => ({
  title,
  kind: "terraform",
  filename: "f.tf",
  content: "",
  rationale: "",
  pathCount,
  riskCovered: coveragePct,
  coveragePct,
});

const path = (id: string, runtimeConfirmed = false): AttackPath => ({
  id,
  score: 0.55,
  runtimeConfirmed,
  nodes: [
    { id: "n1", label: "LoadBalancer", name: "edge-alb", properties: {} },
    { id: "n2", label: "IAM_Role", name: "payments-admin", properties: {} },
  ],
  steps: [],
  remediations: [],
  detections: [],
});

function metricValue(label: string): string {
  const card = screen.getByText(label).closest("div")?.parentElement;
  if (!card) throw new Error(`metric card not found for ${label}`);
  return within(card).getByText(/^[0-9]+%?$/).textContent ?? "";
}

function renderToday(over: Partial<Parameters<typeof TodayView>[0]> = {}) {
  return render(
    <TodayView
      posture={posture}
      risk={risk}
      paths={[path("p1"), path("p2")]}
      plan={[fix("Scope down IAM role web-admin", 0.31, 4), fix("Deny ingress", 0.2, 4), fix("Segment tier", 0.11, 2)]}
      violations={[]}
      onOpenPath={vi.fn()}
      onSeeAllPaths={vi.fn()}
      onOpenTrust={vi.fn()}
      {...over}
    />,
  );
}

describe("TodayView", () => {
  it("leads with the fixes, naming how much risk they remove", () => {
    renderToday();
    expect(screen.getByText("Do these 3 things")).toBeInTheDocument();
    expect(screen.getByText("Scope down IAM role web-admin")).toBeInTheDocument();
    // 31 + 20 + 11 = 62% of risk, across 10 of 14 routes. It reads both as the
    // headline metric and in the sentence under the heading.
    expect(metricValue("Exposure removable today")).toBe("62%");
    expect(screen.getByText(/across 10 of your 14 routes/)).toBeInTheDocument();
  });

  it("counts only the sensitive assets actually reachable", () => {
    // Three crown jewels exist but one is unreachable, so the headline is 2. This
    // is the number that ticks down as routes are cut - unlike a compromise
    // percentage pinned at 100, which can never show progress.
    renderToday();
    expect(metricValue("Sensitive assets reachable")).toBe("2");
    expect(screen.getByText(/worst: account-admin at 97%/)).toBeInTheDocument();
  });

  it("interrupts for routes that are being exercised right now", () => {
    renderToday({ paths: [path("p1", true), path("p2", true), path("p3")] });
    expect(screen.getByText(/2 routes are being exercised right now/)).toBeInTheDocument();
  });

  it("stays quiet when nothing is runtime-confirmed", () => {
    renderToday();
    expect(screen.queryByText(/being exercised right now/)).not.toBeInTheDocument();
  });

  it("surfaces the trust verdict instead of hiding it in diagnostics", () => {
    renderToday({
      calibration: {
        samples: 977,
        brier: 0.029,
        logLoss: 0,
        ece: 0.132,
        meanPredicted: 0.14,
        observedRate: 0.02,
        recommendedScale: 0.14,
        verdict: "overconfident",
        hasData: true,
        bins: [],
        brierRecalibrated: 0.002,
        diagnosis: "recalibrate-first",
        persistent: false,
      },
    });
    expect(screen.getByText("Can you trust these numbers?")).toBeInTheDocument();
    expect(screen.getByText("overconfident")).toBeInTheDocument();
    expect(screen.getByText(/977 tested routes/)).toBeInTheDocument();
  });

  it("degrades honestly when no remediation was generated", () => {
    renderToday({ plan: [] });
    expect(screen.getByText("Nothing to fix")).toBeInTheDocument();
    expect(screen.getByText(/No remediation was generated/)).toBeInTheDocument();
  });
});

// Coverage is what stops an empty board from reading as good news. These pin the two
// states that matter; the quiet one is the whole reason the feature exists.
const sources = (stale: boolean) => [
  { source: "trivy", firstSeen: "", lastSeen: "", events: 1, nodes: 5, edges: 4, stale, silentFor: stale ? "3d" : "" },
  { source: "falco", firstSeen: "", lastSeen: "", events: 1, nodes: 1, edges: 0, stale: false, silentFor: "" },
];

describe("ingest coverage", () => {
  it("names the sources the board was built from", () => {
    renderToday({ coverage: sources(false) });
    expect(screen.getByText(/Built from/)).toBeInTheDocument();
    expect(screen.getByText("trivy")).toBeInTheDocument();
    expect(screen.getByText("falco")).toBeInTheDocument();
  });

  // The case the feature exists for: nothing found AND a source has gone quiet. A green
  // board over a region no collector reached is not good news, and saying so is the only
  // defence against a false negative, which is otherwise invisible.
  it("warns when an empty board rests on a source that stopped reporting", () => {
    renderToday({
      coverage: sources(true),
      posture: { ...posture, activePaths: 0, criticalPaths: 0 },
      paths: [],
      plan: [],
    });
    expect(screen.getByText(/gone quiet/i)).toBeInTheDocument();
    expect(screen.getByText(/cannot show you a route it never sent/i)).toBeInTheDocument();
  });

  // With routes on the board the strip stays informational: the warning is about a
  // silence that could be hiding something, not about silence as such.
  it("does not cry wolf while routes are on the board", () => {
    renderToday({ coverage: sources(true) });
    expect(screen.queryByText(/gone quiet/i)).not.toBeInTheDocument();
  });

  it("renders nothing when no source has ever reported", () => {
    renderToday({ coverage: [] });
    expect(screen.queryByText(/Built from/)).not.toBeInTheDocument();
  });
});
