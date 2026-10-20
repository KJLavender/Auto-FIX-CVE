import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Usage } from "../types.js";

const SKIP_DIRS = new Set(["target", "node_modules", ".git", "vendor"]);

export async function listRustFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) out.push(...(await listRustFiles(path.join(dir, entry.name))));
    } else if (entry.name.endsWith(".rs")) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/** Items named by a `use` tree body: `{a, b as c, d::{e, f}}` → [["a","a"], ["c","b"], ["e","d::e"], ["f","d::f"]]. */
export function useTreeItems(tree: string, prefix = ""): [local: string, path: string][] {
  const t = tree.trim();
  const brace = t.indexOf("{");
  if (brace === -1) {
    const m = t.match(/^([\w:]+?)(?:\s+as\s+(\w+))?$/);
    if (!m || m[1] === "self" || m[1].endsWith("*")) return [];
    const full = prefix + m[1];
    return [[m[2] ?? full.split("::").pop()!, full]];
  }
  const head = t.slice(0, brace).replace(/::$/, "");
  const inner = t.slice(brace + 1, t.lastIndexOf("}"));
  // Split on top-level commas only.
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of inner) {
    if (ch === "{") depth++;
    if (ch === "}") depth--;
    if (ch === "," && depth === 0) {
      parts.push(current);
      current = "";
    } else current += ch;
  }
  parts.push(current);
  const base = prefix + (head ? `${head}::` : "");
  return parts.filter((p) => p.trim()).flatMap((p) => useTreeItems(p, base));
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Finds uses of crates in Rust source: `use crate::{...}` imports (recording
 * each imported item and later references to it) and fully qualified paths
 * like `serde_json::from_str(...)`. Crate names use `_` in code where
 * Cargo.toml may use `-`.
 */
export function findRustUsagesInSource(file: string, source: string, crates: string[]): Map<string, Usage[]> {
  const lines = source.split(/\r?\n/);
  const result = new Map<string, Usage[]>();
  const add = (crate: string, line: number, column: number, symbol: string) =>
    result.set(crate, [
      ...(result.get(crate) ?? []),
      { file, line: line + 1, column, specifier: crate, symbol, snippet: lines[line].trim(), mentionedBy: [] },
    ]);
  const idents = new Map(crates.map((c) => [c.replace(/-/g, "_"), c]));

  const bindings = new Map<string, { crate: string; path: string }>();
  const useLines = new Set<number>();
  // `use` statements can span lines; join until the terminating semicolon.
  for (let i = 0; i < lines.length; i++) {
    const start = lines[i].match(/^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(?:::)?(\w+)(.*)$/);
    if (!start || !idents.has(start[1])) continue;
    let text = start[2];
    const first = i;
    while (!text.includes(";") && i + 1 < lines.length) text += " " + lines[++i].trim();
    for (let l = first; l <= i; l++) useLines.add(l);
    const crate = idents.get(start[1])!;
    const body = text.slice(0, text.indexOf(";")).replace(/^::/, "");
    const alias = body.match(/^\s+as\s+(\w+)\s*$/);
    if (alias || !body.trim()) {
      // `use regex;` / `use regex as re;` binds the crate itself.
      bindings.set(alias?.[1] ?? start[1], { crate, path: "" });
      continue;
    }
    for (const [local, itemPath] of useTreeItems(body)) {
      bindings.set(local, { crate, path: itemPath });
      add(crate, first, 1, itemPath);
    }
  }

  for (let i = 0; i < lines.length; i++) {
    if (useLines.has(i)) continue;
    const code = lines[i].replace(/\/\/.*$/, "");
    // Fully qualified: `serde_json::from_str`, `regex::Regex::new`.
    for (const [ident, crate] of idents) {
      for (const m of code.matchAll(new RegExp(`(?<![\\w:])${escapeRegExp(ident)}::((?:\\w+::)*\\w+)`, "g"))) {
        add(crate, i, m.index + 1, m[1]);
      }
    }
    // Names brought in by `use`: `Regex::new(...)`, `from_str(...)`.
    for (const [local, b] of bindings) {
      if (b.path === "") {
        // A crate alias (`use regex as re;`) is only used through paths: `re::Regex::new`.
        if (idents.has(local)) continue; // already covered by the qualified-path scan above
        for (const m of code.matchAll(new RegExp(`(?<![\\w:])${escapeRegExp(local)}::((?:\\w+::)*\\w+)`, "g"))) {
          add(b.crate, i, m.index + 1, m[1]);
        }
        continue;
      }
      for (const m of code.matchAll(new RegExp(`(?<![\\w:.])${escapeRegExp(local)}\\b(?:::(\\w+))?`, "g"))) {
        add(b.crate, i, m.index + 1, m[1] ? `${b.path}::${m[1]}` : b.path);
      }
    }
  }
  return result;
}

export async function findRustUsages(projectDir: string, crates: string[]): Promise<Map<string, Usage[]>> {
  const merged = new Map<string, Usage[]>();
  if (crates.length === 0) return merged;
  for (const abs of await listRustFiles(projectDir)) {
    const rel = path.relative(projectDir, abs).split(path.sep).join("/");
    for (const [crate, usages] of findRustUsagesInSource(rel, await readFile(abs, "utf8"), crates)) {
      merged.set(crate, [...(merged.get(crate) ?? []), ...usages]);
    }
  }
  return merged;
}
