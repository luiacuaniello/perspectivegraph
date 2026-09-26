// Layout for the graph lens on one route.
import type { Edge, Node } from "../api/client";

// ROUTE_SPACING is the distance between two hops of a laid-out route.
const ROUTE_SPACING = 200;

// routeLayout places a route on one horizontal line and each neighbour beside the route
// node it touches - alternately above and below, three abreast - so the path reads like
// the sentence it is instead of the zig-zag a generic tree layout made of it.
export function routeLayout(route: string[], nodes: Node[], edges: Edge[]): Record<string, { x: number; y: number }> {
  const col = new Map(route.map((id, i) => [id, i]));
  const pos: Record<string, { x: number; y: number }> = {};
  route.forEach((id, i) => {
    pos[id] = { x: i * ROUTE_SPACING, y: 0 };
  });
  const perCol = new Map<number, number>();
  for (const n of nodes) {
    if (col.has(n.id)) continue;
    let j = 0;
    for (const e of edges) {
      if (e.from === n.id && col.has(e.to)) {
        j = col.get(e.to)!;
        break;
      }
      if (e.to === n.id && col.has(e.from)) {
        j = col.get(e.from)!;
        break;
      }
    }
    const k = perCol.get(j) ?? 0;
    perCol.set(j, k + 1);
    const side = k % 2 === 0 ? 1 : -1;
    const slot = Math.floor(k / 2);
    const row = Math.floor(slot / 3) + 1;
    pos[n.id] = { x: j * ROUTE_SPACING + ((slot % 3) - 1) * 70, y: side * row * 90 };
  }
  return pos;
}
