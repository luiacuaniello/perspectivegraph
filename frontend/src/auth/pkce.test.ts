import { describe, it, expect } from "vitest";
import { codeChallenge, generateCodeVerifier, randomString } from "./pkce";

describe("pkce", () => {
  // RFC 7636 Appendix B test vector: this exact verifier must produce this exact
  // S256 challenge, or our redirect won't match what the IdP expects.
  it("derives the S256 challenge per RFC 7636", async () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = await codeChallenge(verifier);
    expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("generates a verifier of valid length and charset", () => {
    const v = generateCodeVerifier();
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
    // PKCE unreserved set; base64url yields A–Z a–z 0–9 - _
    expect(v).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it("produces unique high-entropy strings", () => {
    const a = randomString(32);
    const b = randomString(32);
    expect(a).not.toBe(b);
    expect(a.length).toBe(32);
  });
});
