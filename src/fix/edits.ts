import { existsSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";

export interface Edit {
  file: string;
  /** Exact text to replace; must occur exactly once. Empty creates a new file. */
  search: string;
  replace: string;
}

// Manifests, lockfiles and installed packages are owned by the package manager, never by model edits.
const PROTECTED =
  /(^|\/)(node_modules\/|package\.json$|package-lock\.json$|\.git\/|\.venv\/|pyproject\.toml$|uv\.lock$|poetry\.lock$|Pipfile(\.lock)?$|requirements[^/]*\.txt$|go\.(mod|sum)$|vendor\/|Cargo\.(toml|lock)$|target\/|\.(cs|fs|vb)proj$|Directory\.(Packages|Build)\.props$|packages\.lock\.json$|obj\/)/;

/** Puts files back as recorded by `applyEdits` / `snapshot`; files that did not exist are deleted. */
export async function restoreFiles(originals: Map<string, string | null>): Promise<void> {
  for (const [abs, content] of originals) {
    if (content === null) await rm(abs, { force: true });
    else await writeFile(abs, content, "utf8");
  }
}

/** Records a file's current content (null if missing) unless it was recorded already. */
export async function snapshot(originals: Map<string, string | null>, abs: string): Promise<void> {
  if (!originals.has(abs)) originals.set(abs, existsSync(abs) ? await readFile(abs, "utf8") : null);
}

/** Project-relative paths of recorded files whose content differs from the snapshot. */
export async function changedSince(projectDir: string, originals: Map<string, string | null>): Promise<string[]> {
  const changed: string[] = [];
  for (const [abs, before] of originals) {
    const now = existsSync(abs) ? await readFile(abs, "utf8") : null;
    if (now !== before) changed.push(path.relative(projectDir, abs).split(path.sep).join("/"));
  }
  return changed;
}

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
    await snapshot(originals, abs);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, content, "utf8");
  }
  return [...pending.keys()].map((abs) => path.relative(projectDir, abs).split(path.sep).join("/"));
}
