import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse } from "yaml";
import type { Dependency } from "../types.js";
import { splitNameVersion, toDependencies, type GraphNode, type Root } from "./graph.js";

type DepMap = Record<string, string | { specifier?: string; version: string }>;

interface Importer {
  dependencies?: DepMap;
  devDependencies?: DepMap;
  optionalDependencies?: DepMap;
}

interface PnpmLock {
  lockfileVersion?: string | number;
  importers?: Record<string, Importer>;
  // Single-project v6 lockfiles keep the root dependencies at the top level.
  dependencies?: DepMap;
  devDependencies?: DepMap;
  optionalDependencies?: DepMap;
  packages?: Record<string, { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> }>;
  snapshots?: Record<string, { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string> } | null>;
}

/** `1.2.3(react@18.0.0)` → `1.2.3`; v6 keys also start with `/`. */
function stripPeers(s: string): string {
  return s.replace(/^\//, "").replace(/\(.*$/, "");
}

/** Resolves a dependency reference to a node id; handles aliases like `npm:string-width@4.2.3`. */
function refToId(name: string, ref: string): string | undefined {
  if (/^(link|file|workspace):/.test(ref)) return undefined;
  const clean = stripPeers(ref.replace(/^npm:/, ""));
  return /^\d/.test(clean) ? `${name}@${clean}` : clean;
}

export async function readPnpmLockfile(projectDir: string): Promise<Dependency[]> {
  const lock = parse(await readFile(path.join(projectDir, "pnpm-lock.yaml"), "utf8")) as PnpmLock;
  // v9 keeps the graph in `snapshots`; v6 keeps it in `packages`.
  const graph = lock.snapshots ?? lock.packages ?? {};

  const nodes = new Map<string, GraphNode>();
  for (const [key, entry] of Object.entries(graph)) {
    const id = stripPeers(key);
    const { name, version } = splitNameVersion(id);
    const existing = nodes.get(id) ?? { name, version, children: [] };
    for (const [child, ref] of Object.entries({ ...entry?.dependencies, ...entry?.optionalDependencies })) {
      const childId = refToId(child, ref);
      if (childId && !existing.children.includes(childId)) existing.children.push(childId);
    }
    nodes.set(id, existing);
  }

  const importers = lock.importers ?? { ".": lock };
  const roots: Root[] = [];
  for (const importer of Object.values(importers)) {
    for (const [field, dev] of [["dependencies", false], ["optionalDependencies", false], ["devDependencies", true]] as const) {
      for (const [name, value] of Object.entries(importer[field] ?? {})) {
        const ref = typeof value === "string" ? value : value.version;
        const id = refToId(name, ref);
        if (id) roots.push({ name, id, dev });
      }
    }
  }
  return toDependencies(nodes, roots);
}
