import { describe, expect, it } from "vitest";
import type { Me } from "../api/client";
import { READ_ONLY_REASON, roleReason, writeRestriction } from "./readOnly";

const me = (over: Partial<Me>): Me => ({ subject: "token:1a2b3c4d", tenant: "default", anonymous: false, canWrite: false, ...over });

describe("writeRestriction", () => {
  it("trusts the server's answer over the guess", () => {
    // A viewer token on an authenticated instance: /auth/config alone says nothing is wrong.
    expect(writeRestriction(me({ role: "viewer" }), false)).toBe(roleReason("viewer"));
    expect(writeRestriction(me({ role: "operator" }), false)).toBe(roleReason("operator"));
    // The owner signed in to a published instance can write, whatever the guess says.
    expect(writeRestriction(me({ role: "admin", canWrite: true }), true)).toBeNull();
  });

  it("blames the instance, not a role, for a visitor without a credential", () => {
    expect(writeRestriction(me({ subject: "anonymous", role: "viewer", anonymous: true }), true)).toBe(READ_ONLY_REASON);
  });

  it("falls back to the published-instance guess while the answer is unknown", () => {
    expect(writeRestriction(null, true)).toBe(READ_ONLY_REASON);
    expect(writeRestriction(null, false)).toBeNull();
  });

  it("leaves an open instance writable", () => {
    expect(writeRestriction(me({ subject: "anonymous", anonymous: true, canWrite: true }), false)).toBeNull();
  });
});
