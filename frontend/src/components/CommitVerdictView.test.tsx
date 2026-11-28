import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import CommitVerdictView from "./CommitVerdictView";
import { fetchVerdict, type AttackPath, type CommitVerdict } from "../api/client";

vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  fetchVerdict: vi.fn(),
}));

const ask = vi.mocked(fetchVerdict);

const route = (id: string, target: string, score: number): AttackPath => ({
  id,
  score,
  priority: 70,
  priorityLabel: "P1",
  nodes: [
    { id: `${id}-lb`, label: "LoadBalancer", name: "edge-alb", properties: {} },
    { id: `${id}-t`, label: "IAM_Role", name: target, properties: {} },
  ],
  steps: [{ edgeType: "EXPOSES", from: `${id}-lb`, to: `${id}-t`, probability: score }],
  remediations: [],
  detections: [],
});

const verdict = (over: Partial<CommitVerdict>): CommitVerdict => ({
  slug: "acme/payments-api",
  sha: "3f2a91c0d4e5",
  analysed: true,
  analysedAt: new Date().toISOString(),
  attribution: "diff",
  paths: [],
  routes: [],
  ...over,
});

const commit = { slug: "acme/payments-api", sha: "3f2a91c0d4e5" };

// The page a red check opens says what the check says: which routes this commit answers
// for, which ones only run through it, and that a commit nobody analysed is not clean.
describe("CommitVerdictView", () => {
  // A block, not an expression: a function returned from beforeEach is run as the test's
  // cleanup, and mockReset returns the mock - which then got called once more after each
  // test, outside the component, with nothing to catch its rejection.
  beforeEach(() => {
    ask.mockReset();
  });

  it("keeps a commit the engine never saw apart from a clean one", async () => {
    ask.mockResolvedValue(verdict({ analysed: false }));
    render(<CommitVerdictView commit={commit} analyzedAt="t1" onLookup={() => {}} onOpenPath={() => {}} />);

    expect(await screen.findByText("Not analysed")).toBeInTheDocument();
    expect(screen.getByText(/gate answers unknown and fails closed/)).toBeInTheDocument();
    expect(screen.queryByText("Clean")).not.toBeInTheDocument();
  });

  it("separates the routes the commit opened from the ones that were there before it", async () => {
    ask.mockResolvedValue(
      verdict({
        paths: [route("opened", "payments-admin", 0.6), route("before", "billing-db", 0.4)],
        routes: [
          { pathId: "opened", counts: true, change: "introduced", previousScore: 0 },
          { pathId: "before", counts: false, change: "preexisting", previousScore: 0 },
        ],
      }),
    );
    const open = vi.fn();
    render(<CommitVerdictView commit={commit} analyzedAt="t1" onLookup={() => {}} onOpenPath={open} />);

    expect(await screen.findByText("Blocked")).toBeInTheDocument();
    expect(screen.getByText("1 critical route opened or made likelier by this commit.")).toBeInTheDocument();

    const counted = screen.getByRole("heading", { name: /Counted against this commit/ }).closest("section")!;
    expect(within(counted).getByText("payments-admin")).toBeInTheDocument();
    expect(within(counted).getByText("Opened by this commit")).toBeInTheDocument();
    expect(within(counted).queryByText("billing-db")).not.toBeInTheDocument();

    const already = screen.getByRole("heading", { name: /Already there before it/ }).closest("section")!;
    expect(within(already).getByText("billing-db")).toBeInTheDocument();

    fireEvent.click(within(counted).getByRole("button", { name: /payments-admin/ }));
    expect(open).toHaveBeenCalledWith("opened");
  });

  it("shows how much likelier a worsened route got", async () => {
    ask.mockResolvedValue(
      verdict({
        paths: [route("worse", "payments-admin", 0.55)],
        routes: [{ pathId: "worse", counts: true, change: "worsened", previousScore: 0.2 }],
      }),
    );
    render(<CommitVerdictView commit={commit} analyzedAt="t1" onLookup={() => {}} onOpenPath={() => {}} />);
    expect(await screen.findByText("Made likelier by this commit: 20% before, 55% now")).toBeInTheDocument();
  });

  it("is clean when only routes from before it run through the commit", async () => {
    ask.mockResolvedValue(
      verdict({
        paths: [route("before", "billing-db", 0.4)],
        routes: [{ pathId: "before", counts: false, change: "preexisting", previousScore: 0 }],
      }),
    );
    render(<CommitVerdictView commit={commit} analyzedAt="t1" onLookup={() => {}} onOpenPath={() => {}} />);
    expect(await screen.findByText("Clean")).toBeInTheDocument();
    expect(screen.getByText(/1 critical route that was already there runs through it; it doesn't count\./)).toBeInTheDocument();
  });

  it("does not claim the commit opened anything under the per-commit rule", async () => {
    ask.mockResolvedValue(
      verdict({
        attribution: "commit",
        paths: [route("through", "payments-admin", 0.6)],
        routes: [{ pathId: "through", counts: true, change: "recorded", previousScore: 0 }],
      }),
    );
    render(<CommitVerdictView commit={commit} analyzedAt="t1" onLookup={() => {}} onOpenPath={() => {}} />);
    expect(await screen.findByText(/1 critical route runs through this commit/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Routes through this commit/ })).toBeInTheDocument();
    expect(screen.queryByText(/opened or made likelier/)).not.toBeInTheDocument();
  });

  it("asks again when a new analysis has run", async () => {
    ask.mockResolvedValue(verdict({ analysed: false }));
    const { rerender } = render(<CommitVerdictView commit={commit} analyzedAt="t1" onLookup={() => {}} onOpenPath={() => {}} />);
    await screen.findByText("Not analysed");
    rerender(<CommitVerdictView commit={commit} analyzedAt="t2" onLookup={() => {}} onOpenPath={() => {}} />);
    await vi.waitFor(() => expect(ask).toHaveBeenCalledTimes(2));
    expect(ask).toHaveBeenLastCalledWith(commit.slug, commit.sha);
  });

  it("says so when the engine cannot answer", async () => {
    ask.mockRejectedValue(new Error("GraphQL HTTP 503"));
    render(<CommitVerdictView commit={commit} analyzedAt="t1" onLookup={() => {}} onOpenPath={() => {}} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("GraphQL HTTP 503");
  });

  it("asks for a commit by hand, and refuses one that cannot exist", () => {
    const lookup = vi.fn();
    render(<CommitVerdictView commit={null} analyzedAt={null} onLookup={lookup} onOpenPath={() => {}} />);

    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "acme" } });
    fireEvent.change(screen.getByLabelText("Commit SHA"), { target: { value: "3f2a91c" } });
    fireEvent.click(screen.getByRole("button", { name: "Show the verdict" }));
    expect(screen.getByRole("alert")).toHaveTextContent("owner/name");
    expect(lookup).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: " acme/payments-api " } });
    fireEvent.change(screen.getByLabelText("Commit SHA"), { target: { value: "main" } });
    fireEvent.click(screen.getByRole("button", { name: "Show the verdict" }));
    expect(screen.getByRole("alert")).toHaveTextContent("hexadecimal");

    fireEvent.change(screen.getByLabelText("Commit SHA"), { target: { value: "3f2a91c" } });
    fireEvent.click(screen.getByRole("button", { name: "Show the verdict" }));
    expect(lookup).toHaveBeenCalledWith({ slug: "acme/payments-api", sha: "3f2a91c" });
    expect(ask).not.toHaveBeenCalled();
  });
});
