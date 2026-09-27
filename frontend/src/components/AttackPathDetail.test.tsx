import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import AttackPathDetail from "./AttackPathDetail";
import type { AttackPath } from "../api/client";
import { READ_ONLY_REASON, ReadOnlyContext, roleReason } from "../auth/readOnly";

// The detail panel is where the engine's honesty layers become a claim a human
// reads: the headline exploit score, the epistemic credible interval, and the
// correlation ceiling. Each is shown only when it carries information - a rule
// that is easy to break silently, since a wrong threshold still renders fine.
// These tests pin the display contract rather than the markup.

const base: AttackPath = {
  id: "ap-lb-role",
  score: 0.5,
  runtimeConfirmed: false,
  nodes: [
    { id: "lb", label: "LoadBalancer", name: "edge-lb", properties: {} },
    { id: "role", label: "IAM_Role", name: "admin-role", properties: {} },
  ],
  steps: [
    { edgeType: "EXPOSES", from: "lb", to: "role", probability: 0.5 },
  ],
  remediations: [],
  detections: [],
};

const path = (over: Partial<AttackPath>): AttackPath => ({ ...base, ...over });

describe("AttackPathDetail probability display", () => {
  it("shows the exploit probability as a whole percentage, labelled", () => {
    render(<AttackPathDetail path={path({ score: 0.5 })} />);
    const header = screen.getByRole("banner");
    expect(within(header).getByText("50%")).toBeInTheDocument();
    expect(within(header).getByText(/Exploit probability/)).toBeInTheDocument();
  });

  it("leads with priority when there is one, and names both numbers", () => {
    // The list ranks by priority while the detail used to headline the exploit score, so
    // a route read as "60" in one place and "55%" in the other with nothing saying they
    // were different measures. Both are shown, each under its own name.
    render(<AttackPathDetail path={path({ score: 0.55, priority: 60, priorityLabel: "P2" })} />);
    expect(screen.getByText("Priority")).toBeInTheDocument();
    expect(screen.getByText("P2")).toBeInTheDocument();
    expect(screen.getByText("60")).toBeInTheDocument();
    expect(screen.getByText(/Exploit probability/)).toBeInTheDocument();
    expect(screen.getByText("55%")).toBeInTheDocument();
  });

  it("does not invent a priority the backend did not send", () => {
    render(<AttackPathDetail path={path({ score: 0.5, priority: null })} />);
    expect(screen.queryByText("Priority")).not.toBeInTheDocument();
  });

  it("shows the 90% credible interval when the band is wide enough to inform", () => {
    render(<AttackPathDetail path={path({ scoreCiLow: 0.38, scoreCiHigh: 0.71, confidenceLabel: "low" })} />);
    // A wide band is the whole point of the epistemic layer: surface it.
    expect(screen.getByText(/90% CI 38-71%/)).toBeInTheDocument();
  });

  it("suppresses a degenerate credible interval and falls back to the confidence label", () => {
    // A band narrower than 2 points is noise, not information: showing
    // "90% CI 50-51%" would imply precision the model does not have.
    render(<AttackPathDetail path={path({ scoreCiLow: 0.5, scoreCiHigh: 0.51, confidenceLabel: "high" })} />);
    expect(screen.queryByText(/90% CI/)).not.toBeInTheDocument();
    expect(screen.getByText("high confidence")).toBeInTheDocument();
  });

  it("shows the correlation ceiling only when hops actually share a basis", () => {
    // Same numbers, but without correlatedHops the ceiling is theoretical and
    // must stay hidden - otherwise every path grows a scary second number.
    render(<AttackPathDetail path={path({ score: 0.5, scoreUpperBound: 0.9, correlatedHops: false })} />);
    expect(screen.queryByText(/if correlated/)).not.toBeInTheDocument();
  });

  it("shows the correlation ceiling when hops are correlated and the gap is material", () => {
    render(<AttackPathDetail path={path({ score: 0.5, scoreUpperBound: 0.9, correlatedHops: true })} />);
    expect(screen.getByText(/up to 90% if correlated/)).toBeInTheDocument();
  });

  it("hides the correlation ceiling when the gap is negligible", () => {
    // correlatedHops is true, but a 2-point gap says the independence assumption
    // is barely doing any work - reporting it would be noise.
    render(<AttackPathDetail path={path({ score: 0.5, scoreUpperBound: 0.52, correlatedHops: true })} />);
    expect(screen.queryByText(/if correlated/)).not.toBeInTheDocument();
  });

  it("renders the per-profile breakdown with the blended mixture", () => {
    render(
      <AttackPathDetail
        path={path({
          profileScores: [
            { profile: "commodity", prior: 0.5, score: 0.12 },
            { profile: "apt", prior: 0.15, score: 0.72 },
          ],
          mixtureScore: 0.28,
        })}
      />,
    );
    expect(screen.getByText("Commodity")).toBeInTheDocument();
    expect(screen.getByText("12%")).toBeInTheDocument();
    // "apt" is upper-cased as an acronym, not title-cased.
    expect(screen.getByText("APT")).toBeInTheDocument();
    expect(screen.getByText("72%")).toBeInTheDocument();
    expect(screen.getByText(/blended 28%/)).toBeInTheDocument();
  });

  it("stays coherent when the attacker-marginal exceeds the correlation ceiling", () => {
    // Documented model interaction: scoreUpperBound is the Fréchet ceiling for a
    // FIXED attacker, while mixtureScore marginalizes over attacker capability -
    // a different axis. Under APT-heavy ATTACKER_PROFILE_PRIORS the blended value
    // can legitimately exceed the ceiling, so the two must not be read as one
    // scale. This pins that both are still rendered (no crash, no suppression);
    // if the UI later reconciles them, this test is the place to state the rule.
    render(
      <AttackPathDetail
        path={path({
          score: 0.3,
          scoreUpperBound: 0.5,
          correlatedHops: true,
          mixtureScore: 0.65,
          profileScores: [{ profile: "apt", prior: 0.9, score: 0.7 }],
        })}
      />,
    );
    expect(screen.getByText(/up to 50% if correlated/)).toBeInTheDocument();
    expect(screen.getByText(/blended 65%/)).toBeInTheDocument();
  });

  it("omits the profile row entirely when the backend sends no breakdown", () => {
    render(<AttackPathDetail path={path({ profileScores: null, mixtureScore: null })} />);
    expect(screen.queryByText(/by attacker profile/)).not.toBeInTheDocument();
    expect(screen.queryByText(/blended/)).not.toBeInTheDocument();
  });

  it("flags a runtime-confirmed path by what was observed: an alert", () => {
    // "ACTIVELY EXPLOITED" claimed more than a runtime alert shows - the alert may be the
    // team's own test - and the Today page then had to walk the claim back.
    render(<AttackPathDetail path={path({ runtimeConfirmed: true })} />);
    expect(screen.getByText("Runtime alert on this route")).toBeInTheDocument();
    expect(screen.queryByText(/ACTIVELY EXPLOITED/)).not.toBeInTheDocument();
  });

  it("says when the evidence conflicts instead of showing both claims side by side", () => {
    render(
      <AttackPathDetail
        path={path({ runtimeConfirmed: true, validation: { outcome: "refuted", source: "caldera" } })}
      />,
    );
    expect(screen.getByText("Evidence conflicts")).toBeInTheDocument();
    expect(screen.getByText(/Refuted by/)).toBeInTheDocument();
  });

  it("reads a refuted test on an asset open to anyone as a conflict too", () => {
    // The engine keeps such a path in P1; the header must not show a plain refutation
    // beside a P1 it cannot explain.
    render(
      <AttackPathDetail
        path={path({ runtimeConfirmed: false, directAccess: true, validation: { outcome: "refuted", source: "caldera" } })}
      />,
    );
    expect(screen.getByText("Evidence conflicts")).toBeInTheDocument();
  });
});

// On an instance published read-only every write answers 403. The actions stay on screen -
// they are how a visitor learns what the product does - but disabled, with the reason, so
// pressing one no longer produces an error that makes a working demo look broken.
describe("AttackPathDetail on a read-only instance", () => {
  const writes = [/Validate/, /Open fix PR/, /Suppress \/ triage/, /Create ticket/];

  it("disables every write and says why", () => {
    render(
      <ReadOnlyContext.Provider value={READ_ONLY_REASON}>
        <AttackPathDetail path={base} />
      </ReadOnlyContext.Provider>,
    );
    for (const name of writes) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
    }
    expect(screen.getByText(READ_ONLY_REASON)).toBeInTheDocument();
  });

  it("names the role when it is the role that cannot write", () => {
    // A viewer on a working instance is not on a read-only one: telling them so would send
    // them looking for a setting instead of a different role.
    const reason = roleReason("viewer");
    render(
      <ReadOnlyContext.Provider value={reason}>
        <AttackPathDetail path={base} />
      </ReadOnlyContext.Provider>,
    );
    for (const name of writes) {
      const button = screen.getByRole("button", { name });
      expect(button).toBeDisabled();
      expect(button).toHaveAttribute("title", reason);
    }
    expect(screen.getByText(reason)).toBeInTheDocument();
    expect(screen.queryByText(READ_ONLY_REASON)).not.toBeInTheDocument();
  });

  it("leaves them enabled everywhere else", () => {
    render(<AttackPathDetail path={base} />);
    for (const name of writes) {
      expect(screen.getByRole("button", { name })).toBeEnabled();
    }
    expect(screen.queryByText(READ_ONLY_REASON)).not.toBeInTheDocument();
  });
});

// Multi-account estates. The account is not decoration: `i-…` and `sg-…` are unique
// only within an account, so on an estate that ingests several, "which account" is
// what tells two same-named assets apart - and a route that leaves the account it
// started in is the finding, not a detail. Neither may cost a single-account user
// screen space, which is the half that breaks silently.
describe("AttackPathDetail account display", () => {
  const crossAccount = path({
    nodes: [
      { id: "lb", label: "LoadBalancer", name: "edge-lb", properties: {}, account: "111111111111" },
      { id: "role", label: "IAM_Role", name: "admin-role", properties: {}, account: "222222222222" },
    ],
  });

  it("names the accounts a route runs through", () => {
    render(<AttackPathDetail path={crossAccount} />);
    expect(screen.getByText("111111111111")).toBeInTheDocument();
    expect(screen.getByText("222222222222")).toBeInTheDocument();
  });

  it("calls out a route that crosses an account boundary", () => {
    render(<AttackPathDetail path={crossAccount} />);
    expect(screen.getByText(/crosses 2 accounts/)).toBeInTheDocument();
  });

  it("says nothing about accounts when the whole route is in one", () => {
    const single = path({
      nodes: [
        { id: "lb", label: "LoadBalancer", name: "edge-lb", properties: {}, account: "111111111111" },
        { id: "role", label: "IAM_Role", name: "admin-role", properties: {}, account: "111111111111" },
      ],
    });
    render(<AttackPathDetail path={single} />);
    expect(screen.queryByText(/crosses/)).not.toBeInTheDocument();
  });

  it("shows nothing at all on a single-account estate", () => {
    render(<AttackPathDetail path={base} />);
    expect(screen.queryByText(/crosses/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^\d{12}$/)).not.toBeInTheDocument();
  });
});

// The page reads as an explanation, not a dump of the ontology: one sentence for the
// route, a reason for the band, verbs between assets, and the place the fix cuts.
describe("AttackPathDetail in plain language", () => {
  const log4shell = path({
    score: 0.55,
    priority: 70,
    priorityLabel: "P1",
    priorityReason: "a runtime alert fired on this route: it is happening, not predicted",
    nodes: [
      { id: "lb", label: "LoadBalancer", name: "edge-alb", internetExposed: true, crownJewel: false, runtimeAlert: false },
      { id: "lib", label: "Library", name: "log4j-core@2.14.1", internetExposed: false, crownJewel: false, runtimeAlert: false },
      { id: "cve", label: "CVE", name: "CVE-2021-44228", internetExposed: false, crownJewel: false, runtimeAlert: false },
      { id: "role", label: "IAM_Role", name: "payments-admin", internetExposed: false, crownJewel: true, runtimeAlert: false },
    ],
    steps: [
      { edgeType: "EXPOSES", from: "lb", to: "lib", probability: 0.9 },
      { edgeType: "AFFECTS", from: "lib", to: "cve", probability: 0.9 },
      { edgeType: "EXPLOITS", from: "cve", to: "role", probability: 0.8 },
    ],
    remediations: [
      {
        title: "Deny ingress", kind: "k8s-networkpolicy", filename: "np.yaml", rationale: "cuts the entry",
        content: "a", cut: { from: "lb", to: "lib", type: "EXPOSES" },
      },
    ],
  });

  it("sums the route up in one sentence", () => {
    render(<AttackPathDetail path={log4shell} />);
    expect(
      screen.getByText(
        "From the internet, through edge-alb, an attacker reaches payments-admin in 3 steps, by exploiting CVE-2021-44228.",
      ),
    ).toBeInTheDocument();
  });

  it("says why the path is in its band", () => {
    render(<AttackPathDetail path={log4shell} />);
    expect(screen.getByText(/Why P1:/)).toBeInTheDocument();
    expect(screen.getByText(/a runtime alert fired on this route/)).toBeInTheDocument();
  });

  it("reads the hops as verbs with percentages, not edge types and decimals", () => {
    render(<AttackPathDetail path={log4shell} />);
    expect(screen.getByText("exposes")).toBeInTheDocument();
    expect(screen.getByText("is vulnerable to")).toBeInTheDocument();
    expect(screen.getByText("80%")).toBeInTheDocument();
    expect(screen.queryByText("EXPOSES")).not.toBeInTheDocument();
    expect(screen.queryByText(/p = 0\./)).not.toBeInTheDocument();
    expect(screen.getByText("IAM role")).toBeInTheDocument();
    // The jump from a CVE to a cloud role is the one a reader would not take on faith.
    expect(screen.getByText(/act with payments-admin's credentials/)).toBeInTheDocument();
  });

  it("marks the hop the generated fix cuts", () => {
    render(<AttackPathDetail path={log4shell} />);
    expect(screen.getByText("the fix cuts here")).toBeInTheDocument();
  });

  it("makes applying the fix the primary action when there is one", () => {
    render(<AttackPathDetail path={log4shell} />);
    expect(screen.getByRole("button", { name: /Open fix PR/ }).className).toMatch(/bg-accent/);
  });

  it("keeps fix, detection and evidence in tabs, and switches between them", () => {
    render(<AttackPathDetail path={log4shell} />);
    expect(screen.getByRole("tab", { name: /Fix/ })).toHaveAttribute("aria-selected", "true");
    const tab = screen.getByRole("tab", { name: /Evidence/ });
    const evidence = document.getElementById(tab.getAttribute("aria-controls")!)!;
    expect(evidence).not.toBeVisible();
    fireEvent.click(tab);
    expect(evidence).toBeVisible();
    expect(tab).toHaveAttribute("aria-selected", "true");
  });

  it("holds only tabs in its tablist, and moves between them with the arrow keys", () => {
    // The graph button sat inside the tablist, which axe fails as aria-required-children.
    render(<AttackPathDetail path={log4shell} onShowInGraph={() => {}} />);
    const list = screen.getByRole("tablist", { name: "Path details" });
    expect([...list.children].every((c) => c.getAttribute("role") === "tab")).toBe(true);
    expect(within(list).queryByRole("button", { name: /Show in graph/ })).toBeNull();

    const fix = within(list).getByRole("tab", { name: /Fix/ });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs.map((t) => t.tabIndex)).toEqual([0, -1, -1]);
    fix.focus();
    fireEvent.keyDown(fix, { key: "ArrowLeft" }); // wraps to the last tab
    const evidence = within(list).getByRole("tab", { name: /Evidence/ });
    expect(evidence).toHaveAttribute("aria-selected", "true");
    expect(evidence).toHaveFocus();
    fireEvent.keyDown(evidence, { key: "Home" });
    expect(fix).toHaveAttribute("aria-selected", "true");
    expect(fix).toHaveFocus();
  });

  it("collapses a long generated file behind 'Show all'", () => {
    const long = Array.from({ length: 40 }, (_, i) => `line ${i}`).join("\n");
    render(
      <AttackPathDetail
        path={path({ remediations: [{ title: "t", kind: "terraform", filename: "f.tf", rationale: "r", content: long }] })}
      />,
    );
    expect(screen.queryByText(/line 39/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show all 40 lines" }));
    expect(screen.getByText(/line 39/)).toBeInTheDocument();
  });
});
