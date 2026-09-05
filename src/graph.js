import { readFile } from "node:fs/promises";
import path from "node:path";

/**
 * "Which of MY dependencies dragged this in?"
 *
 * A flagged transitive package is only actionable if you know who asked for it —
 * that is the difference between "we must drop this" and "bump one direct dep".
 * Built from package-lock.json, the one lockfile that records per-entry
 * dependency edges without needing a resolver.
 */
export async function buildGraph(projectDir) {
  const lock = JSON.parse(await readFile(path.join(projectDir, "package-lock.json"), "utf8"));
  const packages = lock.packages ?? {};
  const nameOf = (key) => (key === "" ? lock.name ?? "(root)" : key.split("node_modules/").pop());

  const edges = new Map(); // parent name -> Set(child names)
  const roots = new Set();
  for (const [key, entry] of Object.entries(packages)) {
    const parent = nameOf(key);
    const children = new Set([
      ...Object.keys(entry.dependencies ?? {}),
      ...Object.keys(entry.optionalDependencies ?? {}),
      ...Object.keys(entry.peerDependencies ?? {}),
    ]);
    if (key === "") {
      for (const d of Object.keys(entry.devDependencies ?? {})) children.add(d);
      for (const c of children) roots.add(c);
    }
    edges.set(parent, new Set([...(edges.get(parent) ?? []), ...children]));
  }
  return { root: nameOf(""), edges, roots, versions: new Map(Object.entries(packages).map(([k, v]) => [nameOf(k), v.version])) };
}

/**
 * Shortest dependency paths from the project root to `target`.
 * Breadth-first, so the first path found is the shortest one; capped at `limit`.
 */
export function pathsTo(graph, target, { limit = 5, maxDepth = 12 } = {}) {
  const found = [];
  const queue = [[graph.root]];
  const seen = new Set([graph.root]);
  while (queue.length && found.length < limit) {
    const trail = queue.shift();
    if (trail.length > maxDepth) continue;
    for (const child of graph.edges.get(trail[trail.length - 1]) ?? []) {
      const next = [...trail, child];
      if (child === target) {
        found.push(next);
        if (found.length >= limit) break;
        continue;
      }
      if (seen.has(child)) continue;
      seen.add(child);
      queue.push(next);
    }
  }
  return found;
}

/** The direct dependency (first hop off the root) responsible for each path. */
export function blameDirect(paths) {
  return [...new Set(paths.map((p) => p[1]).filter(Boolean))];
}
