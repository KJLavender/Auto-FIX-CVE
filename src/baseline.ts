import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import type { Finding } from "./types.js";

/** Vulnerabilities already known when the baseline was taken, as `package@version vulnId`. */
export interface Baseline {
  generated: string;
  entries: string[];
}

function key(name: string, version: string, id: string): string {
  return `${name}@${version} ${id}`;
}

export function baselineEntries(findings: Finding[]): string[] {
  return [...new Set(findings.flatMap((f) => f.vulns.map((v) => key(f.dependency.name, f.dependency.version, v.id))))].sort();
}

export async function readBaseline(file: string): Promise<Set<string>> {
  if (!existsSync(file)) return new Set();
  return new Set((JSON.parse(await readFile(file, "utf8")) as Baseline).entries ?? []);
}

export async function writeBaseline(file: string, findings: Finding[]): Promise<number> {
  const entries = baselineEntries(findings);
  await writeFile(file, JSON.stringify({ generated: new Date().toISOString().slice(0, 10), entries }, null, 2) + "\n", "utf8");
  return entries.length;
}

/**
 * Splits findings into what is new since the baseline and what was already
 * known. A package keeps only its new vulnerabilities in `fresh`; a package
 * whose vulnerabilities are all known appears only in `known`.
 */
export function splitByBaseline(findings: Finding[], baseline: Set<string>): { fresh: Finding[]; known: number } {
  let known = 0;
  const fresh: Finding[] = [];
  for (const f of findings) {
    const vulns = f.vulns.filter((v) => !baseline.has(key(f.dependency.name, f.dependency.version, v.id)));
    known += f.vulns.length - vulns.length;
    if (vulns.length) fresh.push({ ...f, vulns });
  }
  return { fresh, known };
}
