import type { Dependency } from "../types.js";
import type { Ecosystem } from "../versions.js";

export interface GraphNode {
  name: string;
  version: string;
  /** Ids of the nodes this package depends on. */
  children: string[];
}

export interface Root {
  /** Name as declared in package.json. */
  name: string;
  /** Node id the declaration resolves to. */
  id: string;
  dev: boolean;
}

/**
 * Turns a resolved dependency graph into the flat list the scanner works on:
 * one entry per name@version, marked direct/dev, with the direct dependencies
 * that pull it in. A package is dev-only when no production root reaches it.
 */
export function toDependencies(nodes: Map<string, GraphNode>, roots: Root[], ecosystem: Ecosystem = "npm"): Dependency[] {
  const introducedBy = new Map<string, Set<string>>();
  const prodReachable = new Set<string>();

  for (const root of roots) {
    if (!nodes.has(root.id)) continue;
    const queue = [root.id];
    const seen = new Set(queue);
    while (queue.length) {
      const id = queue.shift()!;
      if (!introducedBy.has(id)) introducedBy.set(id, new Set());
      introducedBy.get(id)!.add(root.name);
      if (!root.dev) prodReachable.add(id);
      for (const child of nodes.get(id)?.children ?? []) {
        if (nodes.has(child) && !seen.has(child)) {
          seen.add(child);
          queue.push(child);
        }
      }
    }
  }

  const rootIds = new Set(roots.map((r) => r.id));
  const byKey = new Map<string, Dependency>();
  for (const [id, node] of nodes) {
    const key = `${node.name}@${node.version}`;
    let dep = byKey.get(key);
    if (!dep) {
      dep = { ecosystem, name: node.name, version: node.version, paths: [], direct: false, dev: true, introducedBy: [] };
      byKey.set(key, dep);
    }
    if (rootIds.has(id)) dep.direct = true;
    if (prodReachable.has(id)) dep.dev = false;
    for (const r of introducedBy.get(id) ?? []) if (!dep.introducedBy.includes(r)) dep.introducedBy.push(r);
  }
  return [...byKey.values()];
}

/** Splits `name@version` (scoped names keep their leading `@`). */
export function splitNameVersion(id: string): { name: string; version: string } {
  const at = id.lastIndexOf("@");
  return at > 0 ? { name: id.slice(0, at), version: id.slice(at + 1) } : { name: id, version: "" };
}
