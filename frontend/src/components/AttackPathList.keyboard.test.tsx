import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AttackPathList from "./AttackPathList";
import { createSuppression, createTicket, type AttackPath } from "../api/client";
import { READ_ONLY_REASON, ReadOnlyContext } from "../auth/readOnly";

vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  createSuppression: vi.fn(),
  createTicket: vi.fn(),
}));

const route = (id: string, target: string, priority: number): AttackPath => ({
  id,
  score: 0.5,
  priority,
  priorityLabel: "P1",
  runtimeConfirmed: false,
  nodes: [
    { id: `${id}-lb`, label: "LoadBalancer", name: "edge-alb", properties: {} },
    { id: `${id}-t`, label: "IAM_Role", name: target, properties: {} },
  ],
  steps: [{ edgeType: "EXPOSES", from: `${id}-lb`, to: `${id}-t`, probability: 0.5 }],
  remediations: [],
  detections: [],
});

// Two assets, so two groups: the order j and k walk is the order the lines are drawn.
const paths = [route("first", "payments-admin", 90), route("second", "billing-db", 60)];

const line = (container: HTMLElement, id: string) =>
  container.querySelector<HTMLButtonElement>(`button[data-route-id="${id}"]`)!;

beforeEach(() => {
  const store = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, String(v)),
    removeItem: (k: string) => void store.delete(k),
  });
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.mocked(createSuppression).mockReset();
  vi.mocked(createTicket).mockReset();
});

describe("AttackPathList from the keyboard", () => {
  it("moves down and up the lines with j and k, and takes the focus along", () => {
    const move = vi.fn();
    const { container, rerender } = render(
      <AttackPathList paths={paths} selectedId="first" onSelect={() => {}} onMove={move} />,
    );

    fireEvent.keyDown(window, { key: "j" });
    expect(move).toHaveBeenLastCalledWith(paths[1]);
    expect(document.activeElement).toBe(line(container, "second"));

    rerender(<AttackPathList paths={paths} selectedId="second" onSelect={() => {}} onMove={move} />);
    fireEvent.keyDown(window, { key: "j" });
    expect(move).toHaveBeenLastCalledWith(paths[1]); // the last line stays the last

    fireEvent.keyDown(window, { key: "k" });
    expect(move).toHaveBeenLastCalledWith(paths[0]);
  });

  it("starts from the top when nothing is selected", () => {
    const move = vi.fn();
    render(<AttackPathList paths={paths} selectedId={null} onSelect={() => {}} onMove={move} />);
    fireEvent.keyDown(window, { key: "j" });
    expect(move).toHaveBeenCalledWith(paths[0]);
  });

  it("leaves the keys alone while someone types, or holds a modifier", () => {
    const move = vi.fn();
    render(
      <>
        <input aria-label="A question" />
        <AttackPathList paths={paths} selectedId="first" onSelect={() => {}} onMove={move} />
      </>,
    );
    fireEvent.keyDown(screen.getByLabelText("A question"), { key: "j" });
    fireEvent.keyDown(window, { key: "j", metaKey: true });
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(move).not.toHaveBeenCalled();
  });

  it("opens the selected line's Triage with t and its Assign with a, and saves nothing", () => {
    const { container } = render(<AttackPathList paths={paths} selectedId="second" onSelect={() => {}} />);
    const row = line(container, "second").parentElement!;

    fireEvent.keyDown(window, { key: "t" });
    expect(within(row).getByRole("group", { name: /^Triage/ })).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: "Accept risk" })).toBeInTheDocument();
    expect(within(line(container, "first").parentElement!).queryByRole("group")).not.toBeInTheDocument();

    fireEvent.keyDown(window, { key: "a" });
    expect(within(row).getByLabelText("Ticket owner")).toHaveFocus();

    expect(createSuppression).not.toHaveBeenCalled();
    expect(createTicket).not.toHaveBeenCalled();
  });

  it("puts the focus on the options, not on the first of them", () => {
    localStorage.setItem("pg-owner", "dana");
    const { container } = render(<AttackPathList paths={paths} selectedId="first" onSelect={() => {}} />);
    fireEvent.keyDown(window, { key: "t" });
    const group = within(line(container, "first").parentElement!).getByRole("group", { name: /^Triage/ });
    expect(group).toHaveFocus();
  });

  it("offers no actions to a read-only session", () => {
    render(
      <ReadOnlyContext.Provider value={READ_ONLY_REASON}>
        <AttackPathList paths={paths} selectedId="first" onSelect={() => {}} />
      </ReadOnlyContext.Provider>,
    );
    fireEvent.keyDown(window, { key: "t" });
    expect(screen.queryByRole("group")).not.toBeInTheDocument();
  });
});
