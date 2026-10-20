import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import type { Dependency } from "../types.js";
import { normalizeName } from "../versions.js";
import { toDependencies, type GraphNode, type Root } from "./graph.js";

const norm = (name: string) => normalizeName("PyPI", name);

/** Project name from a PEP 508 requirement such as `requests[socks]>=2.25 ; python_version>"3"`. */
export function requirementName(req: string): string | undefined {
  return req.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)?.[1];
}

async function readToml(file: string): Promise<Record<string, any>> {
  return parseToml(await readFile(file, "utf8")) as Record<string, any>;
}

function uniqueByName(nodes: Map<string, GraphNode>): Map<string, string> {
  const byName = new Map<string, string>();
  for (const [id, node] of nodes) byName.set(node.name, id);
  return byName;
}

// ---------------------------------------------------------------- uv.lock

interface UvDep {
  name: string;
  version?: string;
}

interface UvPackage {
  name: string;
  version?: string;
  source?: { virtual?: string; editable?: string; registry?: string };
  dependencies?: UvDep[];
  "optional-dependencies"?: Record<string, UvDep[]>;
  "dev-dependencies"?: Record<string, UvDep[]>;
}

export async function readUvLockfile(projectDir: string): Promise<Dependency[]> {
  const lock = await readToml(path.join(projectDir, "uv.lock"));
  const packages = (lock.package ?? []) as UvPackage[];
  const isProject = (p: UvPackage) => p.source?.virtual !== undefined || p.source?.editable !== undefined;

  const nodes = new Map<string, GraphNode>();
  const idsByName = new Map<string, string[]>();
  for (const p of packages) {
    if (isProject(p)) continue;
    const id = `${norm(p.name)}@${p.version}`;
    nodes.set(id, { name: norm(p.name), version: String(p.version), children: [] });
    idsByName.set(norm(p.name), [...(idsByName.get(norm(p.name)) ?? []), id]);
  }
  // uv only spells out the version when several versions of a package are locked.
  const resolve = (d: UvDep) => (d.version ? `${norm(d.name)}@${d.version}` : idsByName.get(norm(d.name))?.[0]);
  const allDeps = (p: UvPackage) => [...(p.dependencies ?? []), ...Object.values(p["optional-dependencies"] ?? {}).flat()];

  for (const p of packages) {
    if (isProject(p)) continue;
    const node = nodes.get(`${norm(p.name)}@${p.version}`)!;
    for (const d of allDeps(p)) {
      const id = resolve(d);
      if (id && !node.children.includes(id)) node.children.push(id);
    }
  }

  const roots: Root[] = [];
  for (const p of packages.filter(isProject)) {
    for (const d of allDeps(p)) {
      const id = resolve(d);
      if (id) roots.push({ name: norm(d.name), id, dev: false });
    }
    for (const d of Object.values(p["dev-dependencies"] ?? {}).flat()) {
      const id = resolve(d);
      if (id) roots.push({ name: norm(d.name), id, dev: true });
    }
  }
  return toDependencies(nodes, roots, "PyPI");
}

// ---------------------------------------------------------------- poetry.lock

interface PoetryPackage {
  name: string;
  version: string;
  dependencies?: Record<string, unknown>;
}

/** Direct dependencies from pyproject.toml: PEP 621 `[project]` and Poetry's own tables. */
async function pyprojectRoots(projectDir: string): Promise<{ name: string; dev: boolean }[]> {
  const file = path.join(projectDir, "pyproject.toml");
  if (!existsSync(file)) return [];
  const doc = await readToml(file);
  const roots: { name: string; dev: boolean }[] = [];
  const add = (names: Iterable<string>, dev: boolean) => {
    for (const n of names) if (n.toLowerCase() !== "python") roots.push({ name: norm(n), dev });
  };
  add((doc.project?.dependencies ?? []).map(requirementName).filter(Boolean), false);
  add(Object.values(doc.project?.["optional-dependencies"] ?? {}).flat().map((r: any) => requirementName(r)).filter(Boolean) as string[], false);
  add(Object.keys(doc.tool?.poetry?.dependencies ?? {}), false);
  add(Object.keys(doc.tool?.poetry?.["dev-dependencies"] ?? {}), true);
  for (const group of Object.values(doc.tool?.poetry?.group ?? {}) as any[]) add(Object.keys(group.dependencies ?? {}), true);
  for (const reqs of Object.values(doc["dependency-groups"] ?? {}) as unknown[][]) {
    add(reqs.filter((r): r is string => typeof r === "string").map(requirementName).filter(Boolean) as string[], true);
  }
  return roots;
}

export async function readPoetryLockfile(projectDir: string): Promise<Dependency[]> {
  const lock = await readToml(path.join(projectDir, "poetry.lock"));
  const nodes = new Map<string, GraphNode>();
  for (const p of (lock.package ?? []) as PoetryPackage[]) {
    nodes.set(`${norm(p.name)}@${p.version}`, { name: norm(p.name), version: String(p.version), children: [] });
  }
  const byName = uniqueByName(nodes);
  for (const p of (lock.package ?? []) as PoetryPackage[]) {
    const node = nodes.get(`${norm(p.name)}@${p.version}`)!;
    for (const child of Object.keys(p.dependencies ?? {})) {
      const id = byName.get(norm(child));
      if (id && !node.children.includes(id)) node.children.push(id);
    }
  }
  const roots = (await pyprojectRoots(projectDir)).flatMap(({ name, dev }) => {
    const id = byName.get(name);
    return id ? [{ name, id, dev }] : [];
  });
  return toDependencies(nodes, roots, "PyPI");
}

// ---------------------------------------------------------------- Pipfile.lock

export async function readPipfileLock(projectDir: string): Promise<Dependency[]> {
  const lock = JSON.parse(await readFile(path.join(projectDir, "Pipfile.lock"), "utf8")) as Record<
    string,
    Record<string, { version?: string }>
  >;
  // Pipfile.lock is flat: it records what is installed, not who needs it.
  // Pipfile says which packages were asked for directly.
  const pipfile = existsSync(path.join(projectDir, "Pipfile")) ? await readToml(path.join(projectDir, "Pipfile")) : {};
  const declared = new Set([...Object.keys(pipfile.packages ?? {}), ...Object.keys(pipfile["dev-packages"] ?? {})].map(norm));

  const deps = new Map<string, Dependency>();
  for (const [section, dev] of [["default", false], ["develop", true]] as const) {
    for (const [name, entry] of Object.entries(lock[section] ?? {})) {
      const version = entry.version?.replace(/^==/, "");
      if (!version) continue;
      const key = `${norm(name)}@${version}`;
      const existing = deps.get(key);
      if (existing) {
        if (!dev) existing.dev = false;
        continue;
      }
      const direct = declared.size === 0 || declared.has(norm(name));
      deps.set(key, {
        ecosystem: "PyPI",
        name: norm(name),
        version,
        paths: [],
        direct,
        dev,
        introducedBy: direct ? [norm(name)] : [],
      });
    }
  }
  return [...deps.values()];
}

// ---------------------------------------------------------------- requirements.txt

/**
 * Reads pinned `name==version` lines. pip-compile and `uv export` annotate each
 * line with `# via <parent>`, which gives back the dependency graph; a plain
 * hand-written file is treated as all-direct.
 */
export async function readRequirements(projectDir: string, file = "requirements.txt"): Promise<Dependency[]> {
  const lines = (await readFile(path.join(projectDir, file), "utf8")).split(/\r?\n/);
  const pins: { name: string; version: string; via: string[] }[] = [];
  let current: (typeof pins)[number] | undefined;
  let inVia = false;
  for (const raw of lines) {
    const line = raw.trim();
    const pin = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;\\#]+)/);
    if (pin) {
      current = { name: norm(pin[1]), version: pin[2], via: [] };
      pins.push(current);
      inVia = false;
      continue;
    }
    const via = line.match(/^#\s+via\s*(.*)$/);
    if (via && current) {
      inVia = true;
      if (via[1]) current.via.push(via[1].trim());
    } else if (inVia && current && /^#\s+\S/.test(line)) {
      current.via.push(line.replace(/^#\s+/, "").trim());
    } else {
      inVia = false;
    }
  }

  const annotated = pins.some((p) => p.via.length > 0);
  const nodes = new Map<string, GraphNode>();
  for (const p of pins) nodes.set(`${p.name}@${p.version}`, { name: p.name, version: p.version, children: [] });
  const byName = uniqueByName(nodes);
  const roots: Root[] = [];
  for (const p of pins) {
    const id = `${p.name}@${p.version}`;
    const parents = p.via.map((v) => byName.get(norm(v))).filter((x): x is string => x !== undefined);
    for (const parent of parents) nodes.get(parent)!.children.push(id);
    // Lines required by the project itself (or by a `-r` file) are direct.
    const fromProject = p.via.some((v) => v.startsWith("-r") || !byName.has(norm(v)));
    if (!annotated || fromProject || parents.length === 0) roots.push({ name: p.name, id, dev: false });
  }
  return toDependencies(nodes, roots, "PyPI");
}
