import { describe, expect, it } from "vitest";
import { bareName, hopReason } from "./pathLanguage";

describe("pathLanguage", () => {
  it("drops the engine's qualifier before a possessive", () => {
    // It read "act with payments-admin (AdministratorAccess)'s credentials".
    const reason = hopReason(
      { edgeType: "EXPLOITS", from: "cve", to: "role", probability: 0.8 },
      { id: "cve", label: "CVE", name: "CVE-2021-44228", properties: {} },
      { id: "role", label: "IAM_Role", name: "payments-admin (AdministratorAccess)", properties: {} },
    );
    expect(reason).toBe("code execution in the workload lets the attacker act with payments-admin's credentials");
  });

  it("keeps a name without a qualifier as it is", () => {
    expect(bareName("customer-db")).toBe("customer-db");
    expect(bareName("edge-alb (0.0.0.0/0)")).toBe("edge-alb");
  });
});
