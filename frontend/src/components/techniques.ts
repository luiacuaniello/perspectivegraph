import type { AttackPath, AttackTechnique } from "../api/client";

// How many routes use each MITRE ATT&CK technique, most used first. A route counts once per
// technique, however many of its hops use it: the question is how many routes a detection
// for it would watch, not how many hops.

export interface TechniqueCount {
  technique: AttackTechnique;
  routes: number;
}

export function techniqueCounts(paths: AttackPath[]): TechniqueCount[] {
  const byId = new Map<string, TechniqueCount>();
  for (const p of paths) {
    const seen = new Set<string>();
    for (const s of p.steps) {
      const t = s.attack;
      if (!t?.id || seen.has(t.id)) continue;
      seen.add(t.id);
      const c = byId.get(t.id);
      if (c) c.routes++;
      else byId.set(t.id, { technique: t, routes: 1 });
    }
  }
  return [...byId.values()].sort((a, b) => b.routes - a.routes || a.technique.id.localeCompare(b.technique.id));
}
