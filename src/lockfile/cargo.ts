import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import type { Dependency } from "../types.js";
import { toDependencies, type GraphNode, type Root } from "./graph.js";

interface CargoPackage {
  name: string;
  version: string;
  /** Absent for the workspace's own crates. */
  source?: string;
  /** `"name"` or `"name version"` when several versions are locked. */
  dependencies?: string[];
}

/** Dev-dependencies declared by the workspace's crates (Cargo.lock does not mark them). */
async function devDependencyNames(projectDir: string): Promise<Set<string>> {
  const file = path.join(projectDir, "Cargo.toml");
  if (!existsSync(file)) return new Set();
  const doc = parseToml(await readFile(file, "utf8")) as Record<string, any>;
  return new Set(Object.keys(doc["dev-dependencies"] ?? {}));
}

export function parseCargoLock(text: string, devNames: Set<string> = new Set()): Dependency[] {
  const doc = parseToml(text) as { package?: CargoPackage[] };
  const packages = doc.package ?? [];
  const local = packages.filter((p) => !p.source);
  const remote = packages.filter((p) => p.source);

  const nodes = new Map<string, GraphNode>();
  const idsByName = new Map<string, string[]>();
  for (const p of remote) {
    const id = `${p.name}@${p.version}`;
    nodes.set(id, { name: p.name, version: p.version, children: [] });
    idsByName.set(p.name, [...(idsByName.get(p.name) ?? []), id]);
  }
  const resolve = (ref: string) => {
    const [name, version] = ref.split(" ");
    return version ? `${name}@${version}` : idsByName.get(name)?.[0];
  };
  for (const p of remote) {
    const node = nodes.get(`${p.name}@${p.version}`)!;
    for (const ref of p.dependencies ?? []) {
      const id = resolve(ref);
      if (id && nodes.has(id) && !node.children.includes(id)) node.children.push(id);
    }
  }

  // The workspace's own crates are the roots; their registry dependencies are the direct ones.
  const roots: Root[] = [];
  for (const p of local) {
    for (const ref of p.dependencies ?? []) {
      const id = resolve(ref);
      if (id && nodes.has(id)) roots.push({ name: ref.split(" ")[0], id, dev: devNames.has(ref.split(" ")[0]) });
    }
  }
  return toDependencies(nodes, roots, "crates.io");
}

export async function readCargoLock(projectDir: string): Promise<Dependency[]> {
  return parseCargoLock(await readFile(path.join(projectDir, "Cargo.lock"), "utf8"), await devDependencyNames(projectDir));
}
