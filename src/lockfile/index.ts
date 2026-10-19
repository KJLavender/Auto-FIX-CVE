import { existsSync } from "node:fs";
import path from "node:path";
import type { Dependency } from "../types.js";
import { readNpmLockfile } from "./npm.js";
import { readPnpmLockfile } from "./pnpm.js";
import { readYarnLockfile } from "./yarn.js";

export type LockKind = "npm" | "pnpm" | "yarn";

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
];

export function detectLockfile(projectDir: string): { file: string; kind: LockKind } {
  const found = DETECT.find((d) => existsSync(path.join(projectDir, d.file)));
  if (!found) throw new Error(`No lockfile in ${projectDir} (looked for ${DETECT.map((d) => d.file).join(", ")}).`);
  return found;
}

export async function readLockfile(projectDir: string): Promise<Lockfile> {
  const { file, kind } = detectLockfile(projectDir);
  const deps =
    kind === "npm"
      ? await readNpmLockfile(projectDir, file)
      : kind === "pnpm"
        ? await readPnpmLockfile(projectDir)
        : await readYarnLockfile(projectDir);
  return { kind, file, deps };
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
    }
  };
  const i = lines.findIndex(matches);
  return i === -1 ? 1 : i + 1;
}
