import { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { patchApplied } from "./replay.js";
import type { VexJustification } from "../vex.js";

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

/** An accepted risk: a vulnerability the team decided not to fix, with a reason and an optional expiry. */
export interface IgnoreRule {
  /** Vulnerability id or alias, e.g. `GHSA-xxxx` or `CVE-2021-1234`. */
  id: string;
  /** Limit the rule to one package; omitted means any package. */
  package?: string;
  reason: string;
  /** `YYYY-MM-DD`; after this day the vulnerability is reported again. */
  until?: string;
  /**
   * An OpenVEX justification (e.g. `vulnerable_code_not_in_execute_path`). With
   * one, `scan --vex` states the package is not affected, so other scanners
   * (Trivy `--vex`) suppress it too; without one, the risk is only accepted here.
   */
  justification?: VexJustification;
}

/**
 * Guards added at the project's own call sites for vulnerabilities that have
 * no fixed release. They reduce exposure but do not fix the package, so the
 * vulnerabilities stay reported, marked as mitigated while the guards are in place.
 */
export interface MitigationRecord {
  package: string;
  version: string;
  vulns: string[];
  /** Code the guards added, per file; the mitigation counts only while all of it is still there. */
  guards: { file: string; code: string }[];
  explanation: string;
  /** What would still be exploitable, in the model's words. */
  residualRisk: string;
  date: string;
}

export interface Manifest {
  $schema?: string;
  backports: BackportRecord[];
  ignore?: IgnoreRule[];
  mitigations?: MitigationRecord[];
}

/** Lets editors validate and autocomplete the file, ignore rules in particular. */
export const SCHEMA_URL = "https://raw.githubusercontent.com/KJLavender/Auto-FIX-CVE/main/schema/autofix-cve.schema.json";

async function writeManifest(projectDir: string, manifest: Manifest): Promise<void> {
  const { $schema, ...rest } = manifest;
  const doc = { $schema: $schema ?? SCHEMA_URL, ...rest };
  await writeFile(path.join(projectDir, MANIFEST), JSON.stringify(doc, null, 2) + "\n", "utf8");
}

/** Whether a rule still applies on `today` (rules without a reason never apply). */
export function ruleActive(rule: IgnoreRule, today = new Date().toISOString().slice(0, 10)): boolean {
  return Boolean(rule.reason?.trim()) && (!rule.until || rule.until >= today);
}

export async function readManifest(projectDir: string): Promise<Manifest> {
  const file = path.join(projectDir, MANIFEST);
  if (!existsSync(file)) return { backports: [] };
  const manifest = JSON.parse(await readFile(file, "utf8")) as Manifest;
  return { ...manifest, backports: manifest.backports ?? [] };
}

/** Records a backport, merging with an earlier one for the same version instead of replacing it. */
export async function addBackport(projectDir: string, record: BackportRecord): Promise<void> {
  const manifest = await readManifest(projectDir);
  const same = (b: BackportRecord) => b.package === record.package && b.version === record.version;
  const previous = manifest.backports.find(same);
  const union = (a: string[] = [], b: string[]) => [...new Set([...a, ...b])];
  manifest.backports = manifest.backports.filter((b) => !same(b));
  manifest.backports.push({
    ...record,
    vulns: union(previous?.vulns, record.vulns),
    pocs: union(previous?.pocs, record.pocs),
    fixCommits: union(previous?.fixCommits, record.fixCommits),
  });
  await writeManifest(projectDir, manifest);
}

/** Backports whose edits are actually present in node_modules (e.g. not lost to `--ignore-scripts`). */
export async function appliedBackports(projectDir: string, manifest: Manifest): Promise<BackportRecord[]> {
  const applied: BackportRecord[] = [];
  for (const b of manifest.backports) if (await patchApplied(projectDir, b.patch)) applied.push(b);
  return applied;
}

/**
 * Drops the backport for a package version that is no longer installed (e.g.
 * after an upgrade), deleting its patch so postinstall stops warning about it.
 */
export async function removeBackport(projectDir: string, name: string, version: string): Promise<void> {
  const manifest = await readManifest(projectDir);
  const stale = manifest.backports.filter((b) => b.package === name && b.version === version);
  if (stale.length === 0) return;
  for (const b of stale) await rm(path.join(projectDir, b.patch), { force: true });
  manifest.backports = manifest.backports.filter((b) => !stale.includes(b));
  await writeManifest(projectDir, manifest);
}

/** Vulnerability ids already mitigated by a backport for exactly this installed version. */
export function mitigatedIds(manifest: Manifest, name: string, version: string): Set<string> {
  return new Set(manifest.backports.filter((b) => b.package === name && b.version === version).flatMap((b) => b.vulns));
}

/** Records a mitigation, replacing an earlier one for the same package version. */
export async function addMitigation(projectDir: string, record: MitigationRecord): Promise<void> {
  const manifest = await readManifest(projectDir);
  const others = (manifest.mitigations ?? []).filter((m) => !(m.package === record.package && m.version === record.version));
  await writeManifest(projectDir, { ...manifest, mitigations: [...others, record] });
}

/** Mitigations whose guard code is still present in the source, i.e. not edited away since. */
export async function activeMitigations(projectDir: string, manifest: Manifest): Promise<MitigationRecord[]> {
  const out: MitigationRecord[] = [];
  for (const m of manifest.mitigations ?? []) {
    let intact = true;
    for (const g of m.guards) {
      const file = path.join(projectDir, g.file);
      // Line endings may change on checkout (core.autocrlf); compare without them.
      const lf = (s: string) => s.replace(/\r\n/g, "\n");
      const text = existsSync(file) ? lf(await readFile(file, "utf8")) : "";
      if (!text.includes(lf(g.code))) intact = false;
    }
    if (intact) out.push(m);
  }
  return out;
}
