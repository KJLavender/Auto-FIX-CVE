import { existsSync } from "node:fs";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

export interface Edit {
  file: string;
  /** Exact text to replace; must occur exactly once. Empty creates a new file. */
  search: string;
  replace: string;
}

const PROTECTED = /(^|\/)(node_modules\/|package\.json$|package-lock\.json$|\.git\/)/;

export function resolveInProject(projectDir: string, file: string): string {
  const abs = path.resolve(projectDir, file);
  const rel = path.relative(projectDir, abs).split(path.sep).join("/");
  if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error(`${file} is outside the project`);
  if (PROTECTED.test(rel)) throw new Error(`${file} must not be edited by the fixer`);
  return abs;
}

/**
 * Applies search/replace edits. Validates every edit before writing anything,
 * and records each file's original content (null if new) so it can be restored.
 */
export async function applyEdits(
  projectDir: string,
  edits: Edit[],
  originals: Map<string, string | null>,
): Promise<string[]> {
  const pending = new Map<string, string>();
  for (const e of edits) {
    const abs = resolveInProject(projectDir, e.file);
    const exists = pending.has(abs) || existsSync(abs);
    let content = pending.get(abs) ?? (exists ? await readFile(abs, "utf8") : "");
    if (!exists) {
      if (e.search !== "") throw new Error(`${e.file} does not exist`);
      pending.set(abs, e.replace);
      continue;
    }
    let { search, replace } = e;
    if (!content.includes(search) && content.includes("\r\n")) {
      search = search.replace(/\r?\n/g, "\r\n");
      replace = replace.replace(/\r?\n/g, "\r\n");
    }
    const first = content.indexOf(search);
    if (search === "" || first === -1) throw new Error(`search text not found in ${e.file}: ${e.search.slice(0, 200)}`);
    if (content.indexOf(search, first + 1) !== -1) throw new Error(`search text is not unique in ${e.file}`);
    content = content.slice(0, first) + replace + content.slice(first + search.length);
    pending.set(abs, content);
  }

  for (const [abs, content] of pending) {
    if (!originals.has(abs)) originals.set(abs, existsSync(abs) ? await readFile(abs, "utf8") : null);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, content, "utf8");
  }
  return [...pending.keys()].map((abs) => path.relative(projectDir, abs).split(path.sep).join("/"));
}
