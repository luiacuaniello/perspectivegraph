import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import LoginGate from "./LoginGate";
import * as client from "../api/client";
import { READ_ONLY_REASON, roleReason, useReadOnly } from "../auth/readOnly";

// The banner is the only place an unauthenticated instance says so to a human. The
// backend logs it at start-up and /auth/config reports it, but a log scrolls past and an
// endpoint is not read by whoever opens the page - so these pin the three cases that
// decide whether the signal is trustworthy: it appears when the instance IS open, it does
// not appear when a credential is required, and it does not appear when the answer is
// simply unknown. A banner that cries wolf on a network blip teaches people to ignore it.

const BANNER = /requires no credential/i;

// No /auth/me answer unless a test gives one: the gate must work against a backend that
// predates it.
beforeEach(() => {
  vi.spyOn(client, "fetchMe").mockResolvedValue(null);
});
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

  it("shows a read-only notice, not the alarm, on an instance published on purpose", async () => {
    // A published instance reports authRequired false like an open one, but its writes are
    // refused and its ingestion is not exposed. The alarm would tell every visitor of a
    // public demo that it is misconfigured - and name settings only its owner can change.
    vi.spyOn(client, "fetchAuthConfig").mockResolvedValue({
      authRequired: false,
      mode: "token",
      anonymousRole: "viewer",
    } as client.AuthConfig);

    render(
      <LoginGate>
        <p>dashboard</p>
      </LoginGate>,
    );

    expect(await screen.findByRole("status")).toHaveTextContent(/read-only instance/i);
    expect(screen.getByText("dashboard")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText(BANNER)).not.toBeInTheDocument();
  });

  it("tells the dashboard it is read-only only on an instance published on purpose", async () => {
    // The controls decide from this whether to offer writes. An open instance takes writes,
    // so it must not be told otherwise; a published one refuses them.
    const Probe = () => <p>{useReadOnly() ? "read-only" : "writable"}</p>;

    vi.spyOn(client, "fetchAuthConfig").mockResolvedValue({
      authRequired: false,
      mode: "token",
      anonymousRole: "viewer",
    } as client.AuthConfig);
    const published = render(
      <LoginGate>
        <Probe />
      </LoginGate>,
    );
    expect(await screen.findByText("read-only")).toBeInTheDocument();
    published.unmount();

    vi.spyOn(client, "fetchAuthConfig").mockResolvedValue({ authRequired: false, mode: "none" } as client.AuthConfig);
    render(
      <LoginGate>
        <Probe />
      </LoginGate>,
    );
    expect(await screen.findByText("writable")).toBeInTheDocument();
  });

  it("tells a signed-in viewer that their role, not the instance, is why nothing can change", async () => {
    // /auth/config describes the instance and cannot tell a viewer from an admin; the
    // viewer used to be offered every write and meet a 403.
    vi.spyOn(client, "fetchAuthConfig").mockResolvedValue({ authRequired: true, mode: "token" } as client.AuthConfig);
    vi.spyOn(client, "authToken").mockReturnValue("viewer-token");
    vi.spyOn(client, "fetchMe").mockResolvedValue({
      subject: "token:1a2b3c4d",
      role: "viewer",
      tenant: "default",
      anonymous: false,
      canWrite: false,
    });
    const Probe = () => <p>{useReadOnly() ?? "writable"}</p>;

    render(
      <LoginGate>
        <Probe />
      </LoginGate>,
    );

    expect(await screen.findByText(roleReason("viewer"))).toBeInTheDocument();
    expect(screen.queryByText(READ_ONLY_REASON)).not.toBeInTheDocument();
  });

  it("sends a rejected credential back to the gate, and says so", async () => {
    // Anything pasted used to open the dashboard, which then failed every request.
    vi.spyOn(client, "fetchAuthConfig").mockResolvedValue({ authRequired: true, mode: "token" } as client.AuthConfig);
    vi.spyOn(client, "authToken").mockReturnValue("mistyped");
    vi.spyOn(client, "hasRuntimeToken").mockReturnValue(true);
    const cleared = vi.spyOn(client, "clearAuthToken").mockImplementation(() => {});
    vi.spyOn(client, "fetchMe").mockRejectedValue(new client.CredentialRejected("credential not accepted"));

    render(
      <LoginGate>
        <p>dashboard</p>
      </LoginGate>,
    );

    expect(await screen.findByText(/was not accepted/i)).toBeInTheDocument();
    expect(screen.getByText("Sign in to PerspectiveGraph")).toBeInTheDocument();
    expect(screen.queryByText("dashboard")).not.toBeInTheDocument();
    expect(cleared).toHaveBeenCalled();
  });

  it("keeps the dashboard when /auth/me fails for any other reason", async () => {
    // A network blip says nothing about the credential; signing someone out over one would.
    vi.spyOn(client, "fetchAuthConfig").mockResolvedValue({ authRequired: true, mode: "token" } as client.AuthConfig);
    vi.spyOn(client, "authToken").mockReturnValue("good");
    vi.spyOn(client, "hasRuntimeToken").mockReturnValue(true);
    const cleared = vi.spyOn(client, "clearAuthToken").mockImplementation(() => {});
    vi.spyOn(client, "fetchMe").mockRejectedValue(new Error("network"));

    render(
      <LoginGate>
        <p>dashboard</p>
      </LoginGate>,
    );

    expect(await screen.findByText("dashboard")).toBeInTheDocument();
    await waitFor(() => expect(client.fetchMe).toHaveBeenCalled());
    expect(cleared).not.toHaveBeenCalled();
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
