import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse } from "yaml";
import type { Dependency } from "../types.js";
import { toDependencies, type GraphNode, type Root } from "./graph.js";

interface Entry {
  name: string;
  version: string;
  dependencies: Record<string, string>;
}

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function unquote(s: string): string {
  return s.trim().replace(/^"(.*)"$/, "$1");
}

/** `name@range` → name; scoped names keep their `@`. */
function specName(spec: string): string {
  const at = spec.indexOf("@", 1);
  return at === -1 ? spec : spec.slice(0, at);
}

/** Parses the classic (v1) yarn.lock format into spec → entry. */
export function parseYarnV1(text: string): Map<string, Entry> {
  const bySpec = new Map<string, Entry>();
  let current: Entry | undefined;
  let section: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0 && line.endsWith(":")) {
      const specs = line.slice(0, -1).split(/,\s*/).map(unquote);
      // Aliases (`foo@npm:bar@^1`) install the package named after `npm:`.
      const range = specs[0].slice(specName(specs[0]).length + 1);
      current = { name: range.startsWith("npm:") ? specName(range.slice(4)) : specName(specs[0]), version: "", dependencies: {} };
      for (const s of specs) bySpec.set(s, current);
      section = undefined;
    } else if (current && indent === 2) {
      section = line.endsWith(":") ? line.slice(0, -1) : undefined;
      const m = line.match(/^version\s+"?([^"\s]+)"?$/);
      if (m) current.version = m[1];
    } else if (current && indent === 4 && (section === "dependencies" || section === "optionalDependencies")) {
      const m = line.match(/^("?[^"\s]+"?)\s+"?([^"]+)"?$/);
      if (m) current.dependencies[unquote(m[1])] = m[2];
    }
  }
  return bySpec;
}

/** Parses a Yarn Berry (v2+) lockfile, which is YAML, into spec → entry. */
export function parseYarnBerry(text: string): Map<string, Entry> {
  const doc = parse(text) as Record<string, { version?: string; resolution?: string; dependencies?: Record<string, string> }>;
  const bySpec = new Map<string, Entry>();
  for (const [key, value] of Object.entries(doc)) {
    if (key === "__metadata" || !value?.resolution || value.resolution.includes("@workspace:")) continue;
    // `resolution: "lodash@npm:4.17.20"` names the real package, even for aliases.
    const name = value.resolution.slice(0, value.resolution.indexOf("@", 1));
    const entry: Entry = { name, version: String(value.version ?? ""), dependencies: value.dependencies ?? {} };
    for (const spec of key.split(/,\s*/)) bySpec.set(spec.trim(), entry);
  }
  return bySpec;
}

function lookup(bySpec: Map<string, Entry>, name: string, range: string): Entry | undefined {
  return bySpec.get(`${name}@${range}`) ?? bySpec.get(`${name}@npm:${range}`);
}

export async function readYarnLockfile(projectDir: string): Promise<Dependency[]> {
  const text = await readFile(path.join(projectDir, "yarn.lock"), "utf8");
  const bySpec = text.includes("__metadata:") ? parseYarnBerry(text) : parseYarnV1(text);
  const pkg = JSON.parse(await readFile(path.join(projectDir, "package.json"), "utf8")) as PackageJson;

  const ids = new Map<Entry, string>();
  const idOf = (e: Entry) => {
    let id = ids.get(e);
    if (!id) ids.set(e, (id = `${e.name}@${e.version}`));
    return id;
  };
  const nodes = new Map<string, GraphNode>();
  for (const entry of new Set(bySpec.values())) {
    const node = nodes.get(idOf(entry)) ?? { name: entry.name, version: entry.version, children: [] };
    for (const [child, range] of Object.entries(entry.dependencies)) {
      const target = lookup(bySpec, child, range);
      if (target && !node.children.includes(idOf(target))) node.children.push(idOf(target));
    }
    nodes.set(idOf(entry), node);
  }

  const roots: Root[] = [];
  for (const [field, dev] of [["dependencies", false], ["optionalDependencies", false], ["devDependencies", true]] as const) {
    for (const [name, range] of Object.entries(pkg[field] ?? {})) {
      const entry = lookup(bySpec, name, range);
      if (entry) roots.push({ name, id: idOf(entry), dev });
    }
  }
  return toDependencies(nodes, roots);
}
