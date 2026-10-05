import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import LabChecks from "./LabChecks";
import { fetchLabRuns, type LabRun } from "../api/client";

vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  fetchLabRuns: vi.fn(),
}));

const run = (over: Partial<LabRun>): LabRun => ({
  lab: "public-access-lab-aws",
  title: "S3 Block Public Access, on a bucket and on the whole account",
  command: "make public-access-lab-aws",
  region: "eu-north-1",
  engine: "v1.31.0-9-gabc1234",
  ranAt: "2026-10-05T10:00:00Z",
  cost: "free",
  agreed: 2,
  disagreed: 0,
  unsettled: 0,
  checks: [
    { case: "bucketblock", question: "Does a stranger get in?", referee: "an anonymous request to the bucket", aws: "403 AccessDenied", engine: "closed", verdict: "agree" },
    { case: "accountblock", question: "Does a stranger get in?", referee: "an anonymous request to the bucket", aws: "403 AccessDenied", engine: "closed", verdict: "agree" },
  ],
  ...over,
});

// A block, not an expression: beforeEach treats a returned function as a teardown, and
// mockReset returns the mock - which would then be called once more after each test.
beforeEach(() => {
  vi.mocked(fetchLabRuns).mockReset();
});

describe("LabChecks", () => {
  it("adds every lab's answers up, and keeps each check one click away", async () => {
    vi.mocked(fetchLabRuns).mockResolvedValue([
      run({}),
      run({
        lab: "boundary-lab-aws",
        title: "IAM permissions boundaries",
        command: "make boundary-lab-aws",
        agreed: 1,
        checks: [{ case: "role/bounded", question: "Can this identity make itself administrator?", referee: "IAM SimulatePrincipalPolicy", aws: "no privesc", engine: "no privesc", verdict: "agree" }],
      }),
    ]);
    render(<LabChecks />);
    expect(await screen.findByText("3 of 3 answers match AWS's own")).toBeInTheDocument();
    expect(screen.getByText(/not whether a whole route can be walked/)).toBeInTheDocument();
    const lab = screen.getByText("S3 Block Public Access, on a bucket and on the whole account");
    fireEvent.click(lab);
    const table = screen.getByRole("table", { name: /S3 Block Public Access/ });
    expect(within(table).getAllByText("403 AccessDenied")).toHaveLength(2);
    expect(within(table).getAllByText(/asked: an anonymous request to the bucket/)).toHaveLength(2);
    expect(screen.getByText("make public-access-lab-aws")).toBeInTheDocument();
  });

  // A disagreement is the result a lab exists to find: it is counted, not hidden.
  it("says how many answers disagree, in words", async () => {
    vi.mocked(fetchLabRuns).mockResolvedValue([
      run({
        agreed: 1,
        disagreed: 1,
        checks: [
          run({}).checks[0],
          { ...run({}).checks[1], engine: "open", verdict: "disagree" },
        ],
      }),
    ]);
    render(<LabChecks />);
    expect(await screen.findByText("1 of 2 answers match AWS's own")).toBeInTheDocument();
    expect(screen.getByText(/1 disagree/)).toBeInTheDocument();
  });

  it("shows nothing when the build carries no records", async () => {
    vi.mocked(fetchLabRuns).mockResolvedValue([]);
    const { container } = render(<LabChecks />);
    await vi.waitFor(() => expect(fetchLabRuns).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("says so when the records cannot be loaded", async () => {
    vi.mocked(fetchLabRuns).mockRejectedValue(new Error("GraphQL HTTP 502"));
    render(<LabChecks />);
    expect(await screen.findByText(/lab records could not be loaded: GraphQL HTTP 502/)).toBeInTheDocument();
  });
});
