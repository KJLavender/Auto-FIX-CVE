import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Dependency } from "../types.js";

interface LockEntry {
  /** Set when the install location is an alias (`"foo": "npm:bar@^1"`): the real package name. */
  name?: string;
  version?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

interface PackageLock {
  lockfileVersion?: number;
  packages?: Record<string, LockEntry>;
}

const NM = "node_modules/";

function nameFromPath(p: string): string {
  return p.slice(p.lastIndexOf(NM) + NM.length);
}

function parentPath(p: string): string {
  const i = p.lastIndexOf("/" + NM);
  return i === -1 ? "" : p.slice(0, i);
}

/** Mirrors Node's resolution: look in nested node_modules first, then walk up. */
function resolve(packages: Record<string, LockEntry>, from: string, dep: string): string | undefined {
  let base = from;
  for (;;) {
    const candidate = (base ? base + "/" : "") + NM + dep;
    if (packages[candidate]) return candidate;
    if (base === "") return undefined;
    base = parentPath(base);
  }
}

function childNames(entry: LockEntry, includeDev: boolean): string[] {
  return Object.keys({
    ...entry.dependencies,
    ...entry.optionalDependencies,
    ...entry.peerDependencies,
    ...(includeDev ? entry.devDependencies : {}),
  });
}

export async function readNpmLockfile(projectDir: string, file = "package-lock.json"): Promise<Dependency[]> {
  const lockPath = path.join(projectDir, file);
  const lock = JSON.parse(await readFile(lockPath, "utf8")) as PackageLock;
  if (!lock.packages || (lock.lockfileVersion ?? 1) < 2) {
    throw new Error(`${lockPath} is lockfileVersion 1; regenerate it with npm >= 7.`);
  }
  const packages = lock.packages;
  const directNames = childNames(packages[""] ?? {}, true);

  // Walk the graph from each direct dependency to learn who pulls in what.
  const introducedBy = new Map<string, Set<string>>();
  for (const direct of directNames) {
    const start = resolve(packages, "", direct);
    if (!start) continue;
    const queue = [start];
    const seen = new Set(queue);
    while (queue.length) {
      const current = queue.shift()!;
      if (!introducedBy.has(current)) introducedBy.set(current, new Set());
      introducedBy.get(current)!.add(direct);
      for (const child of childNames(packages[current], false)) {
        const resolved = resolve(packages, current, child);
        if (resolved && !seen.has(resolved)) {
          seen.add(resolved);
          queue.push(resolved);
        }
      }
    }
  }

  const byKey = new Map<string, Dependency>();
  for (const [p, entry] of Object.entries(packages)) {
    if (!p.includes(NM) || entry.link || !entry.version) continue;
    const name = entry.name ?? nameFromPath(p);
    const key = `${name}@${entry.version}`;
    let dep = byKey.get(key);
    if (!dep) {
      dep = { ecosystem: "npm", name, version: entry.version, paths: [], direct: false, dev: true, introducedBy: [] };
      byKey.set(key, dep);
    }
    dep.paths.push(p);
    if (directNames.includes(nameFromPath(p)) && p === NM + nameFromPath(p)) dep.direct = true;
    if (!entry.dev) dep.dev = false;
    for (const d of introducedBy.get(p) ?? []) {
      if (!dep.introducedBy.includes(d)) dep.introducedBy.push(d);
    }
  }
  return [...byKey.values()];
}
