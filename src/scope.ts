import { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { auditEvent } from "./audit.js";
import { runFile } from "./fix/exec.js";

/**
 * Scope validation: after a fix, every file that changed must be one the fix
 * meant to change. Anything else, such as an install script editing a tracked
 * file or dropping a CI workflow, means the run is not doing what it claims,
 * and the whole fix is rolled back (fail-closed).
 */
export interface ScopeSnapshot {
  root: string;
  /** Files that were already modified or untracked before the fix, with their content (null: deleted). */
  dirty: Map<string, string | null>;
}

// New untracked files are usually build output; these places are not.
const SENSITIVE = /(^|\/)(\.github\/|\.gitlab-ci\.yml$|\.gitlab\/|\.circleci\/|azure-pipelines\.yml$|Jenkinsfile$|\.npmrc$|\.yarnrc(\.yml)?$|\.pypirc$|pip\.conf$|\.env(\..+)?$|\.husky\/|\.git-hooks\/|Dockerfile$|docker-compose\.ya?ml$|Makefile$|\.vscode\/tasks\.json$)/;

interface StatusEntry {
  path: string;
  untracked: boolean;
}

async function gitStatus(root: string): Promise<StatusEntry[] | undefined> {
  const res = await runFile("git", ["status", "--porcelain=v1", "-z", "--untracked-files=all"], root, 60_000, { trusted: true });
  if (!res.ok) return undefined;
  const parts = res.output.split("\0").filter(Boolean);
  const out: StatusEntry[] = [];
  for (let i = 0; i < parts.length; i++) {
    const code = parts[i].slice(0, 2);
    out.push({ path: path.join(root, parts[i].slice(3)), untracked: code === "??" });
    // A rename or copy is followed by its original path.
    if (code[0] === "R" || code[0] === "C") i++;
  }
  return out;
}

const read = async (file: string) => (existsSync(file) ? readFile(file, "utf8") : null);

/** Undefined outside a git repository: there is no reliable way to tell what changed. */
export async function scopeSnapshot(projectDir: string): Promise<ScopeSnapshot | undefined> {
  const top = await runFile("git", ["rev-parse", "--show-toplevel"], projectDir, 30_000, { trusted: true });
  if (!top.ok) return undefined;
  const root = path.resolve(top.output.trim());
  const status = await gitStatus(root);
  if (!status) return undefined;
  const dirty = new Map<string, string | null>();
  for (const e of status) dirty.set(e.path, await read(e.path));
  return { root, dirty };
}

export interface ScopeResult {
  /** Changed files that the fix did not account for: the reason to roll back. */
  violations: string[];
  /** New untracked files outside sensitive places (typically build output): reported, not fatal. */
  notes: string[];
  /** Everything that changed since the snapshot, for a rollback. */
  changed: string[];
}

/**
 * Compares the tree with the snapshot. `allowed` are absolute paths the fix
 * declared (manifests, lockfiles, edited files), and `allowedPrefixes`
 * directories it owns (e.g. `.autofix-cve/`) or that the user allowed.
 */
export async function checkScope(snap: ScopeSnapshot, allowed: string[], allowedPrefixes: string[]): Promise<ScopeResult> {
  const norm = (p: string) => path.resolve(p).toLowerCase();
  const ok = new Set(allowed.map(norm));
  // Each entry allows that file, or everything under that directory.
  const prefixes = allowedPrefixes.map((p) => norm(p));
  const underAllowed = (file: string) => prefixes.some((p) => norm(file) === p || norm(file).startsWith(p + path.sep));
  const result: ScopeResult = { violations: [], notes: [], changed: [] };
  for (const e of (await gitStatus(snap.root)) ?? []) {
    const before = snap.dirty.has(e.path) ? snap.dirty.get(e.path) : undefined;
    // Already dirty before the fix, and untouched since.
    if (before !== undefined && before === (await read(e.path))) continue;
    result.changed.push(e.path);
    if (ok.has(norm(e.path)) || underAllowed(e.path)) continue;
    const rel = path.relative(snap.root, e.path).split(path.sep).join("/");
    if (!e.untracked || before !== undefined || SENSITIVE.test(rel)) result.violations.push(rel);
    else result.notes.push(rel);
  }
  // A file that was dirty before and is now back to clean also changed.
  for (const [file, before] of snap.dirty) {
    if (!result.changed.includes(file) && before !== (await read(file))) result.changed.push(file);
  }
  auditEvent("scope", { violations: result.violations, notes: result.notes });
  return result;
}

/** Puts every changed file back as it was at the snapshot. */
export async function revertToSnapshot(snap: ScopeSnapshot, changed: string[]): Promise<void> {
  for (const file of changed) {
    if (snap.dirty.has(file)) {
      const before = snap.dirty.get(file)!;
      if (before === null) await rm(file, { force: true });
      else await writeFile(file, before, "utf8");
      continue;
    }
    const tracked = await runFile("git", ["ls-files", "--error-unmatch", "--", file], snap.root, 30_000, { trusted: true });
    if (tracked.ok) await runFile("git", ["checkout", "--", file], snap.root, 60_000, { trusted: true });
    else await rm(file, { force: true });
  }
}

/**
 * Applies the scope check to one finished fix: when it changed anything it
 * did not declare, everything since the snapshot is reverted, `resync`
 * (a reinstall) runs, and the result becomes a failure that names the files.
 */
export async function enforceScope<T extends { status: string; reason?: string; changedFiles: string[] }>(
  projectDir: string,
  snap: ScopeSnapshot | undefined,
  result: T,
  succeeded: string,
  declared: string[],
  allowChanges: string[],
  resync?: () => Promise<unknown>,
): Promise<T> {
  if (!snap || result.status !== succeeded) return result;
  const abs = (p: string) => path.resolve(projectDir, p);
  const scope = await checkScope(
    snap,
    [...declared, ...result.changedFiles].map(abs),
    [abs(".autofix-cve"), ...allowChanges.map(abs)],
  );
  if (!scope.violations.length) return result;
  await revertToSnapshot(snap, scope.changed);
  await resync?.();
  return {
    ...result,
    status: "failed",
    changedFiles: [],
    reason: `fail-closed: files outside this fix changed (${scope.violations.join(", ")}); everything was rolled back`,
  };
}
