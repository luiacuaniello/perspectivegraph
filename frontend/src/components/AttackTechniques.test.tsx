import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import AttackTechniques from "./AttackTechniques";
import { techniqueCounts } from "./techniques";
import type { AttackPath, AttackTechnique } from "../api/client";

const technique = (id: string, name: string): AttackTechnique => ({
  id,
  name,
  tactic: "Initial Access",
  tacticId: "TA0001",
  url: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`,
});

const T1190 = technique("T1190", "Exploit Public-Facing Application");
const T1078 = technique("T1078.004", "Valid Accounts: Cloud Accounts");
const T1611 = technique("T1611", "Escape to Host");

const route = (id: string, techniques: (AttackTechnique | null)[]): AttackPath => ({
  id,
  score: 0.5,
  nodes: [],
  steps: techniques.map((attack, i) => ({ edgeType: "EXPOSES", from: `${id}-${i}`, to: `${id}-${i + 1}`, probability: 0.5, attack })),
  remediations: [],
  detections: [],
});

describe("techniqueCounts", () => {
  it("counts routes, not hops, and puts the most used first", () => {
    const counts = techniqueCounts([
      route("a", [T1190, T1078, T1078]),
      route("b", [T1190, null]),
      route("c", [T1611, T1190]),
    ]);
    expect(counts.map((c) => [c.technique.id, c.routes])).toEqual([
      ["T1190", 3],
      ["T1078.004", 1],
      ["T1611", 1],
    ]);
  });
});

describe("AttackTechniques", () => {
  it("links each technique to MITRE and says how many routes use it", () => {
    render(<AttackTechniques paths={[route("a", [T1190]), route("b", [T1190, T1611])]} openRoutes={2} />);
    const link = screen.getByRole("link", { name: "T1190, Exploit Public-Facing Application, on MITRE ATT&CK" });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1190/");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(link.closest("li")!).getByText("2 routes")).toBeInTheDocument();
    expect(screen.queryByText(/Across the top/)).not.toBeInTheDocument();
  });

  it("says when the list it counts is not every open route", () => {
    render(<AttackTechniques paths={[route("a", [T1190])]} openRoutes={140} />);
    expect(screen.getByText("Across the top 1 of 140 open routes.")).toBeInTheDocument();
  });

  it("shows five, and the rest on request", () => {
    const many = Array.from({ length: 7 }, (_, i) => technique(`T10${i}0`, `Technique ${i}`));
    render(<AttackTechniques paths={[route("a", many)]} openRoutes={1} />);
    expect(screen.getAllByRole("link")).toHaveLength(5);
    fireEvent.click(screen.getByRole("button", { name: "Show all 7" }));
    expect(screen.getAllByRole("link")).toHaveLength(7);
  });

  it("is not there when no hop maps to a technique", () => {
    const { container } = render(<AttackTechniques paths={[route("a", [null])]} openRoutes={1} />);
    expect(container).toBeEmptyDOMElement();
  });
});
