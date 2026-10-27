import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Usage } from "../types.js";

const SKIP_DIRS = new Set(["bin", "obj", "node_modules", ".git", "packages", "TestResults"]);

export async function listCsFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) out.push(...(await listCsFiles(path.join(dir, entry.name))));
    } else if (entry.name.endsWith(".cs")) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/**
 * Namespaces a NuGet package most likely provides. Ids usually are the root
 * namespace (`Newtonsoft.Json`); `.Abstractions` and `.Core` packages usually
 * share the namespace of the package they extend.
 */
export function packageNamespaces(id: string): string[] {
  const stripped = id.replace(/\.(Abstractions|Core)$/i, "");
  return stripped === id ? [id] : [id, stripped];
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Finds uses of NuGet packages in C#: `using` directives (plain, `global`,
 * `static` and aliases), later references through an alias, and fully
 * qualified names like `Newtonsoft.Json.JsonConvert.DeserializeObject(...)`.
 * Matching is by namespace, so it says which files use a package, not which
 * of its types a plain `using` brings in.
 */
export function findCsharpUsagesInSource(file: string, source: string, packages: string[]): Map<string, Usage[]> {
  const lines = source.split(/\r?\n/);
  const result = new Map<string, Usage[]>();
  const add = (pkg: string, line: number, column: number, specifier: string, symbol: string) =>
    result.set(pkg, [...(result.get(pkg) ?? []), { file, line: line + 1, column, specifier, symbol, snippet: lines[line].trim(), mentionedBy: [] }]);

  const spaces = packages.flatMap((p) => packageNamespaces(p).map((ns) => ({ ns, pkg: p })));
  /** Packages whose namespace contains `name`, e.g. `Newtonsoft.Json.Linq` → Newtonsoft.Json. */
  const owners = (name: string) => spaces.filter((s) => name === s.ns || name.startsWith(`${s.ns}.`));

  const aliases = new Map<string, { pkg: string; target: string }>();
  const usingLines = new Set<number>();
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(?:global\s+)?using\s+(?:(static)\s+)?(?:(\w+)\s*=\s*)?([\w.]+)\s*;/.exec(lines[i]);
    if (!m) continue;
    usingLines.add(i);
    const target = m[3];
    for (const { ns, pkg } of owners(target)) {
      if (m[2]) aliases.set(m[2], { pkg, target });
      // Importing the package's root namespace names no API (`*`, like `import *`); the advisory names the package anyway.
      add(pkg, i, lines[i].indexOf(target) + 1, ns, target.slice(ns.length + 1) || "*");
    }
  }

  for (let i = 0; i < lines.length; i++) {
    if (usingLines.has(i)) continue;
    const code = lines[i].replace(/\/\/.*$/, "");
    // Fully qualified: `Newtonsoft.Json.JsonConvert.DeserializeObject`.
    for (const { ns, pkg } of spaces) {
      for (const m of code.matchAll(new RegExp(`(?<![\\w.])${escapeRegExp(ns)}\\.((?:\\w+\\.)*\\w+)`, "g"))) {
        add(pkg, i, m.index + 1, ns, m[1]);
      }
    }
    // Through an alias: `using J = Newtonsoft.Json.JsonConvert;` … `J.DeserializeObject(...)`.
    for (const [alias, { pkg, target }] of aliases) {
      for (const m of code.matchAll(new RegExp(`(?<![\\w.])${escapeRegExp(alias)}\\.(\\w+)`, "g"))) {
        add(pkg, i, m.index + 1, target, `${target.split(".").pop()}.${m[1]}`);
      }
    }
  }
  return result;
}

export async function findCsharpUsages(projectDir: string, packages: string[]): Promise<Map<string, Usage[]>> {
  const merged = new Map<string, Usage[]>();
  if (packages.length === 0) return merged;
  for (const abs of await listCsFiles(projectDir)) {
    const rel = path.relative(projectDir, abs).split(path.sep).join("/");
    for (const [pkg, usages] of findCsharpUsagesInSource(rel, await readFile(abs, "utf8"), packages)) {
      merged.set(pkg, [...(merged.get(pkg) ?? []), ...usages]);
    }
  }
  return merged;
}
