import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Usage } from "../types.js";

const SKIP_DIRS = new Set(["vendor", "node_modules", "testdata", ".git"]);

export async function listGoFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) out.push(...(await listGoFiles(path.join(dir, entry.name))));
    } else if (entry.name.endsWith(".go")) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/** Default package name for an import path: the last element, minus a `/vN` major suffix and `go-` / `.go` decorations. */
export function defaultPackageName(importPath: string): string {
  const parts = importPath.split("/");
  let last = parts[parts.length - 1];
  if (/^v\d+$/.test(last) && parts.length > 1) last = parts[parts.length - 2];
  return last.replace(/^go-/, "").replace(/[.-]go$/, "").replace(/[^A-Za-z0-9_]/g, "_");
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Finds uses of the given modules in Go source: `import "mod/pkg"` and
 * `import alias "mod/pkg"` (single or grouped), then `pkg.Symbol` references.
 * Dot and blank imports are reported as the import itself.
 */
export function findGoUsagesInSource(file: string, source: string, modules: string[]): Map<string, Usage[]> {
  const lines = source.split(/\r?\n/);
  const result = new Map<string, Usage[]>();
  // The longest module path wins: golang.org/x/net/v2 over golang.org/x/net.
  const owner = (importPath: string) =>
    modules.filter((m) => importPath === m || importPath.startsWith(m + "/")).sort((a, b) => b.length - a.length)[0];
  const add = (mod: string, u: Usage) => result.set(mod, [...(result.get(mod) ?? []), u]);

  const bindings = new Map<string, { module: string; importPath: string }>();
  const importLines = new Set<number>();
  let inBlock = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\/\/.*$/, "").trim();
    if (/^import\s*\($/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ")") {
      inBlock = false;
      continue;
    }
    const spec = inBlock ? line : line.match(/^import\s+(.*)$/)?.[1];
    const m = spec?.match(/^(?:([A-Za-z_][\w]*|\.|_)\s+)?"([^"]+)"$/);
    if (!m) continue;
    const mod = owner(m[2]);
    if (!mod) continue;
    importLines.add(i);
    const alias = m[1];
    if (alias === "_" || alias === ".") {
      add(mod, { file, line: i + 1, column: 1, specifier: m[2], symbol: alias === "_" ? "(blank import)" : "(dot import)", snippet: lines[i].trim(), mentionedBy: [] });
      continue;
    }
    bindings.set(alias ?? defaultPackageName(m[2]), { module: mod, importPath: m[2] });
  }

  for (let i = 0; i < lines.length; i++) {
    if (importLines.has(i)) continue;
    const code = lines[i].replace(/\/\/.*$/, "");
    for (const [name, b] of bindings) {
      const re = new RegExp(`(?<![\\w.])${escapeRegExp(name)}\\.([A-Z]\\w*)`, "g");
      for (const m of code.matchAll(re)) {
        add(b.module, { file, line: i + 1, column: m.index + 1, specifier: b.importPath, symbol: m[1], snippet: lines[i].trim(), mentionedBy: [] });
      }
    }
  }
  return result;
}

export async function findGoUsages(projectDir: string, modules: string[]): Promise<Map<string, Usage[]>> {
  const merged = new Map<string, Usage[]>();
  if (modules.length === 0) return merged;
  for (const abs of await listGoFiles(projectDir)) {
    const rel = path.relative(projectDir, abs).split(path.sep).join("/");
    for (const [mod, usages] of findGoUsagesInSource(rel, await readFile(abs, "utf8"), modules)) {
      merged.set(mod, [...(merged.get(mod) ?? []), ...usages]);
    }
  }
  return merged;
}
