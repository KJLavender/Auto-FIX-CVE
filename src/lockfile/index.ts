import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import path from "node:path";
import type { Dependency } from "../types.js";
import { normalizeName } from "../versions.js";
import { readCargoLock } from "./cargo.js";
import { readGoMod } from "./go.js";
import { readNpmLockfile } from "./npm.js";
import { readPnpmLockfile } from "./pnpm.js";
import { readPipfileLock, readPoetryLockfile, readRequirements, readUvLockfile } from "./python.js";
import { readYarnLockfile } from "./yarn.js";

export type LockKind = "npm" | "pnpm" | "yarn" | "uv" | "poetry" | "pipenv" | "requirements" | "go" | "cargo";

export interface Lockfile {
  kind: LockKind;
  /** File name relative to the project, e.g. `pnpm-lock.yaml`. */
  file: string;
  deps: Dependency[];
}

const DETECT: { file: string; kind: LockKind }[] = [
  { file: "package-lock.json", kind: "npm" },
  { file: "npm-shrinkwrap.json", kind: "npm" },
  { file: "pnpm-lock.yaml", kind: "pnpm" },
  { file: "yarn.lock", kind: "yarn" },
  { file: "uv.lock", kind: "uv" },
  { file: "poetry.lock", kind: "poetry" },
  { file: "Pipfile.lock", kind: "pipenv" },
  { file: "requirements.txt", kind: "requirements" },
  { file: "go.mod", kind: "go" },
  { file: "Cargo.lock", kind: "cargo" },
];

const JS_KINDS: LockKind[] = ["npm", "pnpm", "yarn"];
const PY_KINDS: LockKind[] = ["uv", "poetry", "pipenv", "requirements"];

export interface LockRef {
  file: string;
  kind: LockKind;
}

/**
 * Every lockfile in a directory, one per ecosystem: a repo with a JS frontend
 * and a Python backend side by side gets both. Within an ecosystem the first
 * match wins (a real lockfile beats requirements.txt).
 */
export function detectLockfiles(projectDir: string): LockRef[] {
  const found = DETECT.filter((d) => existsSync(path.join(projectDir, d.file)));
  const js = found.find((d) => JS_KINDS.includes(d.kind));
  const py = found.find((d) => PY_KINDS.includes(d.kind));
  const go = found.find((d) => d.kind === "go");
  const rust = found.find((d) => d.kind === "cargo");
  return [js, py, go, rust].filter((d): d is LockRef => d !== undefined);
}

export function detectLockfile(projectDir: string): LockRef {
  const [found] = detectLockfiles(projectDir);
  if (!found) throw new Error(`No lockfile in ${projectDir} (looked for ${DETECT.map((d) => d.file).join(", ")}).`);
  return found;
}

const SKIP_DIRS = new Set(["node_modules", ".git", ".venv", "venv", "env", "__pycache__", "dist", "build", "site-packages", ".tox", "coverage"]);

/** Directories under `root` (inclusive) that contain a lockfile. */
export async function discoverProjects(root: string, maxDepth = 6): Promise<{ dir: string; lock: LockRef }[]> {
  const out: { dir: string; lock: LockRef }[] = [];
  const walk = async (dir: string, depth: number) => {
    for (const lock of detectLockfiles(dir)) out.push({ dir, lock });
    if (depth >= maxDepth) return;
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory() && !SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) {
        await walk(path.join(dir, entry.name), depth + 1);
      }
    }
  };
  await walk(root, 0);
  return out;
}

export async function readLockfile(projectDir: string, ref: LockRef = detectLockfile(projectDir)): Promise<Lockfile> {
  const { file, kind } = ref;
  const readers: Record<LockKind, () => Promise<Dependency[]>> = {
    npm: () => readNpmLockfile(projectDir, file),
    pnpm: () => readPnpmLockfile(projectDir),
    yarn: () => readYarnLockfile(projectDir),
    uv: () => readUvLockfile(projectDir),
    poetry: () => readPoetryLockfile(projectDir),
    pipenv: () => readPipfileLock(projectDir),
    requirements: () => readRequirements(projectDir, file),
    go: () => readGoMod(projectDir),
    cargo: () => readCargoLock(projectDir),
  };
  return { kind, file, deps: await readers[kind]() };
}

/** 1-based line of a package's entry, so code scanning alerts land on it. */
export function lockfileLine(kind: LockKind, lines: string[], name: string, version: string): number {
  const matches = (l: string) => {
    const t = l.trimStart();
    switch (kind) {
      case "npm":
        return t.startsWith(`"node_modules/${name}"`);
      case "pnpm":
        return t.startsWith(`${name}@${version}`) || t.startsWith(`'${name}@${version}`) || t.startsWith(`/${name}@${version}`);
      case "yarn":
        return l === t && (t.startsWith(`${name}@`) || t.startsWith(`"${name}@`));
      case "uv":
      case "poetry":
      case "cargo":
        return normalizeName("PyPI", t.match(/^name = "([^"]+)"$/)?.[1] ?? "") === name;
      case "pipenv":
        return normalizeName("PyPI", t.match(/^"([^"]+)": \{/)?.[1] ?? "") === name;
      case "go": {
        // `module vX` inside a require block, or `require module vX` on one line.
        const words = t.split(/\s+/);
        const [mod, ver] = words[0] === "require" ? words.slice(1) : words;
        return mod === name && ver?.startsWith("v") === true;
      }
      case "requirements":
        return normalizeName("PyPI", t.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)?.[1] ?? "") === name && t.includes(version);
    }
  };
  const i = lines.findIndex(matches);
  return i === -1 ? 1 : i + 1;
}
