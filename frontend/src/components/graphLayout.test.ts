import { describe, expect, it } from "vitest";
import { routeLayout } from "./graphLayout";
import type { Edge, Node } from "../api/client";

const node = (id: string): Node => ({ id, label: "Container", name: id, internetExposed: false, crownJewel: false, runtimeAlert: false });
const edge = (from: string, to: string): Edge => ({ from, to, type: "CONNECTS_TO", probability: 0.5 });

// The route reads left to right on one line, and a neighbour sits beside the hop it hangs
// off - not wherever a generic tree layout put it, which drew a five-hop route as a zig-zag.
describe("routeLayout", () => {
  const route = ["a", "b", "c"];
  const nodes = ["a", "b", "c", "n1", "n2", "n3"].map(node);
  const edges = [edge("a", "b"), edge("b", "c"), edge("b", "n1"), edge("n2", "b"), edge("c", "n3")];
  const pos = routeLayout(route, nodes, edges);

  it("puts the route on one line, in order", () => {
    expect(pos.a.y).toBe(0);
    expect(pos.b.y).toBe(0);
    expect(pos.c.y).toBe(0);
    expect(pos.a.x).toBeLessThan(pos.b.x);
    expect(pos.b.x).toBeLessThan(pos.c.x);
  });

  it("puts a neighbour beside its hop, off the line, on alternating sides", () => {
    for (const id of ["n1", "n2"]) {
      expect(Math.abs(pos[id].x - pos.b.x)).toBeLessThan(100);
      expect(pos[id].y).not.toBe(0);
    }
    expect(Math.sign(pos.n1.y)).not.toBe(Math.sign(pos.n2.y));
    expect(Math.abs(pos.n3.x - pos.c.x)).toBeLessThan(100);
  });
});
