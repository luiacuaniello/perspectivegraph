import { describe, expect, it } from "vitest";
import { hashFor, linkToPath, parseHash } from "./routeHash";

describe("routeHash", () => {
  it("names one route on the paths view", () => {
    expect(parseHash("#paths/ap-edge-alb-payments-admin-9ebc68f4")).toEqual({
      view: "paths",
      pathId: "ap-edge-alb-payments-admin-9ebc68f4",
    });
    expect(parseHash("#paths")).toEqual({ view: "paths", pathId: null });
    expect(parseHash("#paths/")).toEqual({ view: "paths", pathId: null });
  });

  it("keeps the old hashes and ignores a route on views that have none", () => {
    expect(parseHash("#graph")).toEqual({ view: "paths", pathId: null });
    expect(parseHash("#overview")).toEqual({ view: "today", pathId: null });
    expect(parseHash("#accuracy/ap-1")).toEqual({ view: "accuracy", pathId: null });
    // The page was called Trust; its links still arrive.
    expect(parseHash("#trust")).toEqual({ view: "accuracy", pathId: null });
    expect(parseHash("")).toEqual({ view: "today", pathId: null });
    expect(parseHash("#nonsense")).toEqual({ view: "today", pathId: null });
  });

  it("round-trips an id that needs escaping, and survives a malformed one", () => {
    const odd = "ap-a/b c%";
    expect(parseHash(`#${hashFor("paths", odd)}`).pathId).toBe(odd);
    expect(parseHash("#paths/ap-%zz").pathId).toBe("ap-%zz");
  });

  it("links a route absolutely, and only on the paths view", () => {
    expect(hashFor("today", "ap-1")).toBe("today");
    expect(linkToPath("ap-1", { origin: "https://demo.example", pathname: "/", search: "" })).toBe(
      "https://demo.example/#paths/ap-1",
    );
  });
});
