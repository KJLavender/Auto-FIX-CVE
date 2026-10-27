import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Dependency } from "../types.js";
import { toDependencies, type GraphNode, type Root } from "./graph.js";

/**
 * NuGet package ids are case-insensitive; graphs and lookups use the
 * lower-cased id while the dependency keeps the casing the lockfile uses.
 */
const key = (name: string, version: string) => `${name.toLowerCase()}@${version}`;

interface LockEntry {
  type: "Direct" | "Transitive" | "Project" | "CentralTransitive";
  resolved?: string;
  dependencies?: Record<string, string>;
}

/** `packages.lock.json` (RestorePackagesWithLockFile), merged over every target framework and runtime. */
export function parseNugetLock(text: string): Dependency[] {
  const doc = JSON.parse(text) as { dependencies?: Record<string, Record<string, LockEntry>> };
  const nodes = new Map<string, GraphNode>();
  const roots: Root[] = [];
  const resolvedByName = new Map<string, string>();
  const targets = Object.values(doc.dependencies ?? {});
  for (const target of targets) {
    for (const [name, e] of Object.entries(target)) if (e.resolved) resolvedByName.set(name.toLowerCase(), e.resolved);
  }
  for (const target of targets) {
    for (const [name, e] of Object.entries(target)) {
      if (e.type === "Project" || !e.resolved) continue;
      const id = key(name, e.resolved);
      const node = nodes.get(id) ?? { name, version: e.resolved, children: [] };
      for (const child of Object.keys(e.dependencies ?? {})) {
        const v = resolvedByName.get(child.toLowerCase());
        const childId = v && key(child, v);
        if (childId && !node.children.includes(childId)) node.children.push(childId);
      }
      nodes.set(id, node);
      if (e.type === "Direct" && !roots.some((r) => r.id === id)) roots.push({ name, id, dev: false });
    }
  }
  return toDependencies(nodes, roots, "NuGet");
}

interface Assets {
  targets?: Record<string, Record<string, { type?: string; dependencies?: Record<string, string> }>>;
  project?: { frameworks?: Record<string, { dependencies?: Record<string, { target?: string; suppressParent?: string }> }> };
}

/** `obj/project.assets.json`, which every `dotnet restore` writes even without a lockfile. */
export function parseProjectAssets(text: string): Dependency[] {
  const doc = JSON.parse(text) as Assets;
  const nodes = new Map<string, GraphNode>();
  const versionByName = new Map<string, string>();
  const targets = Object.values(doc.targets ?? {});
  for (const target of targets) {
    for (const [id, e] of Object.entries(target)) {
      if (e.type !== "package") continue;
      const [name, version] = id.split("/");
      versionByName.set(name.toLowerCase(), version);
      if (!nodes.has(key(name, version))) nodes.set(key(name, version), { name, version, children: [] });
    }
  }
  for (const target of targets) {
    for (const [id, e] of Object.entries(target)) {
      if (e.type !== "package") continue;
      const [name, version] = id.split("/");
      const node = nodes.get(key(name, version))!;
      for (const child of Object.keys(e.dependencies ?? {})) {
        const v = versionByName.get(child.toLowerCase());
        const childId = v && key(child, v);
        if (childId && nodes.has(childId) && !node.children.includes(childId)) node.children.push(childId);
      }
    }
  }
  const roots: Root[] = [];
  for (const fw of Object.values(doc.project?.frameworks ?? {})) {
    for (const [name, d] of Object.entries(fw.dependencies ?? {})) {
      const v = versionByName.get(name.toLowerCase());
      if (d.target !== "Package" || !v || roots.some((r) => r.id === key(name, v))) continue;
      // PrivateAssets="all" (analyzers, build tools) never reach the built app.
      roots.push({ name, id: key(name, v), dev: d.suppressParent === "All" });
    }
  }
  return toDependencies(nodes, roots, "NuGet");
}

export async function readNugetLock(projectDir: string, file: string): Promise<Dependency[]> {
  const text = await readFile(path.join(projectDir, file), "utf8");
  return file.endsWith("project.assets.json") ? parseProjectAssets(text) : parseNugetLock(text);
}
