import { existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { Usage } from "../types.js";
import { normalizeName } from "../versions.js";

const SKIP_DIRS = new Set(["node_modules", "__pycache__", "site-packages", "build", "dist", "venv", "env", ".git", ".tox"]);

// Distributions whose import name differs from the project name. Used when no
// virtualenv metadata is available to read `top_level.txt` from.
const KNOWN_MODULES: Record<string, string[]> = {
  pyyaml: ["yaml"],
  pillow: ["PIL"],
  beautifulsoup4: ["bs4"],
  "scikit-learn": ["sklearn"],
  "opencv-python": ["cv2"],
  "opencv-python-headless": ["cv2"],
  "python-dateutil": ["dateutil"],
  pyjwt: ["jwt"],
  protobuf: ["google.protobuf"],
  pycryptodome: ["Crypto"],
  pycryptodomex: ["Cryptodome"],
  pyopenssl: ["OpenSSL"],
  dnspython: ["dns"],
  gitpython: ["git"],
  "python-jose": ["jose"],
  "python-multipart": ["multipart"],
  "psycopg2-binary": ["psycopg2"],
  "msgpack-python": ["msgpack"],
  setuptools: ["setuptools", "pkg_resources"],
  attrs: ["attr", "attrs"],
  "typing-extensions": ["typing_extensions"],
  pymongo: ["pymongo", "bson", "gridfs"],
  "ruamel-yaml": ["ruamel.yaml"],
  "google-cloud-storage": ["google.cloud.storage"],
};

/** Reads `top_level.txt` from a local virtualenv, the authoritative list of a distribution's modules. */
async function venvModules(projectDir: string): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  const candidates: string[] = [];
  for (const venv of [".venv", "venv", "env"]) {
    candidates.push(path.join(projectDir, venv, "Lib", "site-packages"));
    const lib = path.join(projectDir, venv, "lib");
    if (existsSync(lib)) for (const py of await readdir(lib)) candidates.push(path.join(lib, py, "site-packages"));
  }
  for (const dir of candidates.filter((d) => existsSync(d))) {
    for (const entry of await readdir(dir)) {
      const m = entry.match(/^(.+?)-[^-]+\.dist-info$/);
      if (!m) continue;
      const topLevel = path.join(dir, entry, "top_level.txt");
      if (!existsSync(topLevel)) continue;
      const modules = (await readFile(topLevel, "utf8")).split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (modules.length) out.set(normalizeName("PyPI", m[1]), modules);
    }
  }
  return out;
}

export async function importNames(projectDir: string, distributions: string[]): Promise<Map<string, string[]>> {
  const fromVenv = await venvModules(projectDir);
  const out = new Map<string, string[]>();
  for (const d of distributions) {
    const n = normalizeName("PyPI", d);
    out.set(n, fromVenv.get(n) ?? KNOWN_MODULES[n] ?? [n.replace(/-/g, "_")]);
  }
  return out;
}

async function listPythonFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) out.push(...(await listPythonFiles(path.join(dir, entry.name))));
    } else if (entry.name.endsWith(".py")) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

interface Binding {
  local: string;
  /** Imported name for `from x import y`, or `*` for a module bound by `import x`. */
  imported: string;
  module: string;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Finds uses of the given modules in Python source. A regex scan rather than
 * a parser: it understands `import a.b as c` and `from a import (x, y as z)`,
 * then reports `c.attr`, `x(...)` and bare references. Like the JS analysis it
 * ignores scoping, preferring an extra hit to a missed vulnerable call.
 */
export function findPythonUsagesInSource(file: string, source: string, modules: Map<string, string[]>): Map<string, Usage[]> {
  const lines = source.split(/\r?\n/);
  const result = new Map<string, Usage[]>();
  // Join parenthesized `from x import (\n a,\n b)` so each import is on one logical line.
  const logical: { text: string; line: number; end: number }[] = [];
  for (let i = 0; i < lines.length; i++) {
    let text = lines[i];
    const start = i;
    if (/^\s*from\s+\S+\s+import\s*\(/.test(text)) {
      while (!text.includes(")") && i + 1 < lines.length) text += " " + lines[++i].trim();
    }
    logical.push({ text, line: start, end: i });
  }

  const owner = (mod: string) => {
    for (const [dist, mods] of modules) if (mods.some((m) => mod === m || mod.startsWith(m + "."))) return dist;
    return undefined;
  };

  const bindings = new Map<string, Binding & { dist: string }>();
  const importLines = new Set<number>();
  for (const { text, line, end } of logical) {
    const markImport = () => {
      for (let l = line; l <= end; l++) importLines.add(l);
    };
    const code = text.replace(/#.*$/, "");
    const imp = code.match(/^\s*import\s+(.+)$/);
    if (imp) {
      for (const part of imp[1].split(",")) {
        const m = part.trim().match(/^([\w.]+)(?:\s+as\s+(\w+))?$/);
        const dist = m && owner(m[1]);
        if (!m || !dist) continue;
        markImport();
        // `import a.b` binds `a`; `import a.b as c` binds `c` to the submodule.
        bindings.set(m[2] ?? m[1].split(".")[0], { local: m[2] ?? m[1].split(".")[0], imported: "*", module: m[1], dist });
      }
      continue;
    }
    const from = code.match(/^\s*from\s+([\w.]+)\s+import\s+\(?([^)]*)\)?/);
    const dist = from && owner(from[1]);
    if (!from || !dist) continue;
    markImport();
    for (const part of from[2].split(",")) {
      const m = part.trim().match(/^(\w+|\*)(?:\s+as\s+(\w+))?$/);
      if (!m || m[1] === "*") continue;
      bindings.set(m[2] ?? m[1], { local: m[2] ?? m[1], imported: m[1], module: from[1], dist });
    }
  }

  for (let i = 0; i < lines.length; i++) {
    if (importLines.has(i)) continue;
    const code = lines[i].replace(/#.*$/, "");
    for (const b of bindings.values()) {
      const re = new RegExp(`(?<![\\w.])${escapeRegExp(b.local)}\\b(\\.(\\w+))?`, "g");
      for (const m of code.matchAll(re)) {
        const symbol = b.imported === "*" ? (m[2] ?? "(module)") : b.imported;
        const list = result.get(b.dist) ?? [];
        list.push({ file, line: i + 1, column: m.index + 1, specifier: b.module, symbol, snippet: lines[i].trim(), mentionedBy: [] });
        result.set(b.dist, list);
      }
    }
  }
  return result;
}

export async function findPythonUsages(projectDir: string, distributions: string[]): Promise<Map<string, Usage[]>> {
  const merged = new Map<string, Usage[]>();
  if (distributions.length === 0) return merged;
  const modules = await importNames(projectDir, distributions);
  for (const abs of await listPythonFiles(projectDir)) {
    const rel = path.relative(projectDir, abs).split(path.sep).join("/");
    for (const [dist, usages] of findPythonUsagesInSource(rel, await readFile(abs, "utf8"), modules)) {
      merged.set(dist, [...(merged.get(dist) ?? []), ...usages]);
    }
  }
  return merged;
}
