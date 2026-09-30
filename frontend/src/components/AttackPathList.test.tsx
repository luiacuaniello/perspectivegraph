import { fireEvent, render, screen, within } from "@testing-library/react";
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

  it("reads a direct-access path as open, not as a zero-hop route from itself", () => {
    // A crown jewel open to anyone is its own path: one node, no steps. Rendered like any
    // other it read "from exports-bucket · 0 hops".
    const open: AttackPath = {
      ...route,
      id: "ap-exports",
      score: 1,
      runtimeConfirmed: false,
      directAccess: true,
      nodes: [{ id: "b", label: "Bucket", name: "exports-bucket", properties: {} }],
      steps: [],
    };
    render(<AttackPathList paths={[open]} selectedId={null} onSelect={() => {}} />);
    const row = screen.getByRole("button", { name: /exports-bucket/ });
    expect(row).toHaveTextContent("open to anyone · direct access");
    expect(row).not.toHaveTextContent("0 hops");
  });

  it("does not paint a live route green because a tester could not walk it", () => {
    // Refuted is green - suppress it as a false positive. On a route with a runtime alert
    // that is the one reading the evidence rules out.
    const refuted = (p: AttackPath): AttackPath => ({
      ...p,
      validation: { outcome: "refuted", source: "caldera-bas", evidence: "", testedAt: "" },
    });
    const { rerender } = render(<AttackPathList paths={[refuted(route)]} selectedId={null} onSelect={() => {}} />);
    expect(screen.getByRole("button", { name: /payments-admin/ })).toHaveTextContent("Evidence conflicts");
    expect(screen.queryByText("Refuted")).toBeNull();

    rerender(
      <AttackPathList paths={[refuted({ ...route, runtimeConfirmed: false })]} selectedId={null} onSelect={() => {}} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Refuted by tests \(1\)/ }));
    expect(screen.getByRole("button", { name: /payments-admin/ })).toHaveTextContent("Refuted");
  });

  it("groups the routes to one asset under it, in the engine's order", () => {
    // cluster-admin reached four ways read as four unrelated rows. The question is what you
    // stand to lose, and by how many routes.
    const to = (id: string, target: { id: string; name: string }, entry: string, priority: number): AttackPath => ({
      ...route,
      id,
      priority,
      priorityLabel: priority >= 70 ? "P1" : "P2",
      runtimeConfirmed: false,
      nodes: [
        { id: `e-${id}`, label: "LoadBalancer", name: entry, properties: {} },
        { id: target.id, label: "IAM_Role", name: target.name, properties: {} },
      ],
      steps: [{ edgeType: "EXPOSES", from: `e-${id}`, to: target.id, probability: 0.9 }],
    });
    const admin = { id: "role-admin", name: "account-admin" };
    const db = { id: "db", name: "customer-db" };
    render(
      <AttackPathList
        paths={[to("ap-1", admin, "edge-alb", 90), to("ap-2", db, "web-lb", 80), to("ap-3", admin, "deployer", 60)]}
        selectedId="ap-3"
        onSelect={() => {}}
      />,
    );
    const headings = screen.getAllByRole("heading", { level: 3 });
    expect(headings.map((h) => h.textContent)).toEqual(["1account-admin2 routes", "2customer-db"]);
    const adminGroup = screen.getByRole("region", { name: /account-admin/ });
    const lines = within(adminGroup).getAllByRole("button").filter((b) => b.dataset.routeId);
    expect(lines.map((b) => b.dataset.routeId)).toEqual(["ap-1", "ap-3"]);
    expect(lines[1]).toHaveAttribute("aria-current", "true");
    // Each line still names its target for a screen reader, though the heading shows it.
    expect(within(adminGroup).getByRole("button", { name: /^account-admin, from deployer · 1 hop/ })).toBe(lines[1]);
  });

  it("sets refuted routes apart, closed, and opens them when one is chosen", () => {
    const refuted: AttackPath = {
      ...route,
      id: "ap-refuted",
      runtimeConfirmed: false,
      validation: { outcome: "refuted", source: "caldera-bas", evidence: "", testedAt: "" },
    };
    const { rerender } = render(<AttackPathList paths={[refuted]} selectedId={null} onSelect={() => {}} />);
    const toggle = screen.getByRole("button", { name: /Refuted by tests \(1\)/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("button", { name: /payments-admin/ })).toBeNull();
    // Named here, since no asset heading carries it.
    fireEvent.click(toggle);
    expect(screen.getByRole("button", { name: /payments-admin/ })).toHaveTextContent("payments-admin (AdministratorAccess)");
    fireEvent.click(toggle);
    expect(screen.queryByRole("button", { name: /payments-admin/ })).toBeNull();

    // A link to a refuted route, or a click from Today, must not land on a closed section.
    rerender(<AttackPathList paths={[refuted]} selectedId="ap-refuted" onSelect={() => {}} />);
    expect(screen.getByRole("button", { name: /payments-admin/ })).toHaveAttribute("aria-current", "true");
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
