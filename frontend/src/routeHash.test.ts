import { describe, expect, it } from "vitest";
import { hashFor, linkToPath, parseHash, validSha, validSlug } from "./routeHash";

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

  it("names a commit on the verdict page, the SHA last", () => {
    expect(parseHash("#verdict/acme/payments-api/3f2a91c")).toEqual({
      view: "verdict",
      pathId: null,
      commit: { slug: "acme/payments-api", sha: "3f2a91c" },
    });
    // A GitLab project path has subgroups.
    expect(parseHash("#verdict/group/sub/project/abcdef1234").commit).toEqual({ slug: "group/sub/project", sha: "abcdef1234" });
    expect(parseHash("#verdict/acme/my%2Erepo/3f2a91c").commit).toEqual({ slug: "acme/my.repo", sha: "3f2a91c" });
  });

  it("opens the form, not a guess, for a commit that cannot exist", () => {
    expect(parseHash("#verdict")).toEqual({ view: "verdict", pathId: null, commit: null });
    expect(parseHash("#verdict/acme/3f2a91c").commit).toBeNull();
    expect(parseHash("#verdict/acme/web/main").commit).toBeNull();
    expect(parseHash("#verdict/acme/../3f2a91c").commit).toBeNull();
    expect(parseHash("#verdict/acme/web%3Fx%3D1/3f2a91c").commit).toBeNull();
  });

  it("round-trips a commit through its link", () => {
    const commit = { slug: "group/sub/project", sha: "3f2a91c0d4" };
    expect(hashFor("verdict", null, commit)).toBe("verdict/group/sub/project/3f2a91c0d4");
    expect(parseHash(`#${hashFor("verdict", null, commit)}`).commit).toEqual(commit);
    expect(hashFor("verdict")).toBe("verdict");
    expect(validSlug("acme/web") && validSha("3f2a91c")).toBe(true);
    expect(validSlug("acme") || validSha("3f2a91")).toBe(false);
  });
});
