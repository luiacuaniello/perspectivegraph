import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import LoginGate from "./LoginGate";
import * as client from "../api/client";

// The banner is the only place an unauthenticated instance says so to a human. The
// backend logs it at start-up and /auth/config reports it, but a log scrolls past and an
// endpoint is not read by whoever opens the page - so these pin the three cases that
// decide whether the signal is trustworthy: it appears when the instance IS open, it does
// not appear when a credential is required, and it does not appear when the answer is
// simply unknown. A banner that cries wolf on a network blip teaches people to ignore it.

const BANNER = /requires no credential/i;

afterEach(() => vi.restoreAllMocks());

describe("LoginGate", () => {
  it("warns when the instance requires no credential", async () => {
    vi.spyOn(client, "fetchAuthConfig").mockResolvedValue({
      authRequired: false,
      mode: "none",
    } as client.AuthConfig);

    render(
      <LoginGate>
        <p>dashboard</p>
      </LoginGate>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(BANNER);
    expect(screen.getByText("dashboard")).toBeInTheDocument();
  });

  it("does not warn when a credential is required", async () => {
    vi.spyOn(client, "fetchAuthConfig").mockResolvedValue({
      authRequired: true,
      mode: "token",
    } as client.AuthConfig);

    render(
      <LoginGate>
        <p>dashboard</p>
      </LoginGate>,
    );

    await waitFor(() => expect(screen.queryByText("dashboard")).not.toBeInTheDocument());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("stays silent when /auth/config could not be reached", async () => {
    // The gate falls back to "open" so the dashboard still renders, but a failed fetch is
    // not evidence that the instance is open - and saying so would be the false alarm
    // that makes the real one ignorable.
    vi.spyOn(client, "fetchAuthConfig").mockRejectedValue(new Error("network"));

    render(
      <LoginGate>
        <p>dashboard</p>
      </LoginGate>,
    );

    expect(await screen.findByText("dashboard")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
