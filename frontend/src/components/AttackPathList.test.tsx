import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AttackPathList from "./AttackPathList";
import type { AttackPath } from "../api/client";
import { READ_ONLY_REASON, ReadOnlyContext } from "../auth/readOnly";

const route: AttackPath = {
  id: "ap-edge-admin",
  score: 0.55,
  priority: 60,
  priorityLabel: "P2",
  runtimeConfirmed: true,
  nodes: [
    { id: "lb", label: "LoadBalancer", name: "edge-alb (0.0.0.0/0)", properties: {} },
    { id: "c", label: "Container", name: "payments", properties: {} },
    { id: "role", label: "IAM_Role", name: "payments-admin (AdministratorAccess)", properties: {} },
  ],
  steps: [
    { edgeType: "EXPOSES", from: "lb", to: "c", probability: 0.9 },
    { edgeType: "ASSUMES", from: "c", to: "role", probability: 0.6 },
  ],
  remediations: [],
  detections: [],
};

// The row actions remember the owner's name in localStorage, and the test runtime's global
// has no methods; a small in-memory store stands in for the browser's.
beforeEach(() => {
  const store = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, String(v)),
    removeItem: (k: string) => void store.delete(k),
  });
});
afterEach(() => vi.unstubAllGlobals());

describe("AttackPathList", () => {
  it("shows both ends of a route in full", () => {
    // The row used to cut both names to fit one line - "edge-al… → payments-admi…" - so
    // the two things a route IS were the two things the list could not show. The
    // qualifiers matter most: "(0.0.0.0/0)" and "(AdministratorAccess)" are what make it
    // serious.
    const { container } = render(<AttackPathList paths={[route]} selectedId={null} onSelect={() => {}} />);
    const row = screen.getByRole("button", { name: /payments-admin/ });
    expect(row).toHaveTextContent("payments-admin (AdministratorAccess)");
    expect(row).toHaveTextContent("from edge-alb (0.0.0.0/0) · 2 hops");
    expect(container.querySelector(".truncate")).toBeNull();
  });

  it("offers row actions on an ordinary instance", () => {
    render(<AttackPathList paths={[route]} selectedId={null} onSelect={() => {}} />);
    expect(screen.getByRole("button", { name: "Triage" })).toBeInTheDocument();
  });

  it("does not offer row actions when this tab cannot write", () => {
    // They reveal on hover; one that appears only to refuse is noise in a list.
    render(
      <ReadOnlyContext.Provider value={READ_ONLY_REASON}>
        <AttackPathList paths={[route]} selectedId={null} onSelect={() => {}} />
      </ReadOnlyContext.Provider>,
    );
    expect(screen.queryByRole("button", { name: "Triage" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Assign" })).not.toBeInTheDocument();
  });
});
