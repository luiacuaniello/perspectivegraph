import { beforeEach, describe, expect, it } from "vitest";
import { authToken, clearAuthToken, exportUrl, hasRuntimeToken, humanDuration, setAuthToken } from "./client";

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
