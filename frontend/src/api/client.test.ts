import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  authToken,
  clearAuthToken,
  CredentialRejected,
  exportUrl,
  fetchMe,
  hasRuntimeToken,
  humanDuration,
  setAuthToken,
} from "./client";

// client.ts is the contract layer between the dashboard and the API. Its pure
// helpers are small but load-bearing: humanDuration renders the "how long has
// this path been open" figure a responder triages on, and the token helpers
// decide whether the UI believes the user is signed in.

describe("humanDuration", () => {
  it("renders sub-minute spans in seconds", () => {
    expect(humanDuration(0)).toBe("0s");
    expect(humanDuration(45)).toBe("45s");
    expect(humanDuration(59.4)).toBe("59s");
  });

  it("switches to minutes at a minute and to hours at an hour", () => {
    expect(humanDuration(60)).toBe("1m");
    expect(humanDuration(3599)).toBe("60m");
    expect(humanDuration(3600)).toBe("1h");
  });

  it("keeps hours readable up to two days, then switches to days", () => {
    // 48h is the boundary: below it hours stay more legible than "2.0d".
    expect(humanDuration(47 * 3600)).toBe("47h");
    expect(humanDuration(48 * 3600)).toBe("2.0d");
  });

  it("drops the decimal once a span passes ten days", () => {
    // "4.2d" is useful precision; "37.4d" is false precision for a stale path.
    expect(humanDuration(4.2 * 86400)).toBe("4.2d");
    expect(humanDuration(37 * 86400)).toBe("37d");
  });
});

describe("auth token handling", () => {
  beforeEach(() => {
    clearAuthToken();
  });

  it("round-trips a runtime token and reports it as runtime-acquired", () => {
    expect(hasRuntimeToken()).toBe(false);
    setAuthToken("tok-123");
    expect(authToken()).toBe("tok-123");
    // Drives whether the UI offers a "sign out" control at all.
    expect(hasRuntimeToken()).toBe(true);
  });

  it("clearing a token signs the user out", () => {
    setAuthToken("tok-123");
    clearAuthToken();
    expect(hasRuntimeToken()).toBe(false);
    // authToken may still fall back to a build-time token, but the runtime
    // session is gone - that distinction is what hasRuntimeToken exists for.
    expect(authToken()).toBeUndefined();
  });
});

describe("exportUrl", () => {
  it("builds same-origin download paths for both export kinds", () => {
    // Same-origin matters: these are downloaded with the session's credentials.
    expect(exportUrl("ndjson")).toBe("/export/ndjson");
    expect(exportUrl("oscal")).toBe("/export/oscal");
  });
});

// fetchMe separates the one answer that is a verdict on the credential (401) from every
// answer that is not. Collapsing them would either sign someone out over a network blip or
// leave a mistyped token looking signed in.
describe("fetchMe", () => {
  const answer = (status: number, body: string, contentType = "application/json") =>
    vi.fn().mockResolvedValue(new Response(body, { status, headers: { "Content-Type": contentType } }));

  beforeEach(() => clearAuthToken());
  afterEach(() => vi.unstubAllGlobals());

  it("sends this tab's credential and returns what it resolved to", async () => {
    setAuthToken("tok-123");
    const fetch = answer(200, JSON.stringify({ subject: "token:1a2b3c4d", role: "viewer", tenant: "default", anonymous: false, canWrite: false }));
    vi.stubGlobal("fetch", fetch);

    expect(await fetchMe()).toMatchObject({ role: "viewer", canWrite: false });
    expect(fetch.mock.calls[0][0]).toBe("/auth/me");
    expect(fetch.mock.calls[0][1].headers.Authorization).toBe("Bearer tok-123");
  });

  it("rejects on 401, and only on 401", async () => {
    vi.stubGlobal("fetch", answer(401, '{"errors":[{"message":"unauthorized"}]}'));
    await expect(fetchMe()).rejects.toBeInstanceOf(CredentialRejected);
  });

  it("answers unknown for a backend without the endpoint, a proxy that serves the page, or no network", async () => {
    vi.stubGlobal("fetch", answer(404, "404 page not found", "text/plain"));
    expect(await fetchMe()).toBeNull();

    vi.stubGlobal("fetch", answer(200, "<!doctype html><html></html>", "text/html"));
    expect(await fetchMe()).toBeNull();

    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    expect(await fetchMe()).toBeNull();
  });
});
