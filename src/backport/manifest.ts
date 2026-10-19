import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { patchApplied } from "./replay.js";

export const MANIFEST = ".autofix-cve.json";

export interface BackportRecord {
  package: string;
  version: string;
  /** Vulnerabilities fixed by the patch and proven by a PoC that failed before and passes after. */
  vulns: string[];
  patch: string;
  pocs: string[];
  fixCommits: string[];
  date: string;
}

export interface Manifest {
  backports: BackportRecord[];
}

export async function readManifest(projectDir: string): Promise<Manifest> {
  const file = path.join(projectDir, MANIFEST);
  if (!existsSync(file)) return { backports: [] };
  return JSON.parse(await readFile(file, "utf8")) as Manifest;
}

export async function addBackport(projectDir: string, record: BackportRecord): Promise<void> {
  const manifest = await readManifest(projectDir);
  manifest.backports = manifest.backports.filter((b) => !(b.package === record.package && b.version === record.version));
  manifest.backports.push(record);
  await writeFile(path.join(projectDir, MANIFEST), JSON.stringify(manifest, null, 2) + "\n", "utf8");
}

/** Backports whose edits are actually present in node_modules (e.g. not lost to `--ignore-scripts`). */
export async function appliedBackports(projectDir: string, manifest: Manifest): Promise<BackportRecord[]> {
  const applied: BackportRecord[] = [];
  for (const b of manifest.backports) if (await patchApplied(projectDir, b.patch)) applied.push(b);
  return applied;
}

/** Vulnerability ids already mitigated by a backport for exactly this installed version. */
export function mitigatedIds(manifest: Manifest, name: string, version: string): Set<string> {
  return new Set(manifest.backports.filter((b) => b.package === name && b.version === version).flatMap((b) => b.vulns));
}
