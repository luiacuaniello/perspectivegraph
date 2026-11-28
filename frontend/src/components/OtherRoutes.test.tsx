import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import OtherRoutes from "./OtherRoutes";
import { fetchOtherRoutes, type AttackPath, type RouteSketch } from "../api/client";

vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  fetchOtherRoutes: vi.fn(),
}));

const ask = vi.mocked(fetchOtherRoutes);

const path: AttackPath = {
  id: "ap-this",
  score: 0.6,
  nodes: [
    { id: "lb", label: "LoadBalancer", name: "edge-alb", properties: {} },
    { id: "role", label: "IAM_Role", name: "payments-admin", properties: {} },
  ],
  steps: [{ edgeType: "EXPOSES", from: "lb", to: "role", probability: 0.6 }],
  remediations: [],
  detections: [],
};

const sketch = (id: string, entry: string, via: string[], score: number, suppressed = false): RouteSketch => ({
  id,
  score,
  suppressed,
  nodes: [
    { id: `${id}-e`, name: entry, label: "LoadBalancer" },
    ...via.map((v, i) => ({ id: `${id}-${i}`, name: v, label: "Container" })),
    { id: "role", name: "payments-admin", label: "IAM_Role" },
  ],
  steps: Array.from({ length: via.length + 1 }, () => ({ edgeType: "EXPOSES" })),
});

// Closing one route can leave the asset reachable another way. The section asks the engine
// when asked, and says how its answer is ordered and what in it is off the board.
describe("OtherRoutes", () => {
  beforeEach(() => {
    ask.mockReset();
  });

  it("asks nothing until asked: it is a heavy query, and the detail changes on every key", () => {
    render(<OtherRoutes path={path} isListed={() => true} onOpenPath={() => {}} />);
    expect(ask).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Look for other routes" })).toBeInTheDocument();
  });

  it("lists the other routes to the asset, not this one, and opens the ones on the list", async () => {
    ask.mockResolvedValue([
      sketch("ap-this", "edge-alb", [], 0.6),
      sketch("ap-listed", "public-api", ["web-1"], 0.45),
      sketch("ap-unlisted", "edge-alb", ["web-2", "worker"], 0.2, true),
    ]);
    const open = vi.fn();
    render(<OtherRoutes path={path} isListed={(id) => id === "ap-listed"} onOpenPath={open} />);
    fireEvent.click(screen.getByRole("button", { name: "Look for other routes" }));

    expect(await screen.findByText("web-1")).toBeInTheDocument();
    expect(ask).toHaveBeenCalledWith("role", 6);
    expect(screen.getAllByRole("listitem")).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: /public-api/ }));
    expect(open).toHaveBeenCalledWith("ap-listed");

    // Off the board and off the list: shown, said so, and not a link to nowhere.
    expect(screen.getByText(/web-2 → worker · taken off the board · not on the list/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /web-2/ })).not.toBeInTheDocument();
  });

  it("says when this is the only way in", async () => {
    ask.mockResolvedValue([sketch("ap-this", "edge-alb", [], 0.6)]);
    render(<OtherRoutes path={path} isListed={() => true} onOpenPath={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Look for other routes" }));
    expect(await screen.findByText(/finds no other route to it/)).toBeInTheDocument();
  });

  it("says so when the engine is too busy to answer", async () => {
    ask.mockRejectedValue(new Error("server busy: try again"));
    render(<OtherRoutes path={path} isListed={() => true} onOpenPath={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Look for other routes" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("server busy: try again");
  });
});
