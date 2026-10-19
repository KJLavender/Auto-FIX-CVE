import semver from "semver";
import { appliedBackports, mitigatedIds, readManifest } from "./backport/manifest.js";
import { findUsages } from "./impact/analyze.js";
import { readNpmLockfile } from "./lockfile/npm.js";
import { OsvClient } from "./osv/client.js";
import type { Finding, Reachability, Usage, Vulnerability } from "./types.js";

export interface ScanOptions {
  includeDev: boolean;
}

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MODERATE: 2, MEDIUM: 2, LOW: 1 };
const REACH_RANK: Record<Reachability, number> = { likely: 2, imported: 1, "not-imported": 0 };

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Builds a matcher for an API name inside advisory prose. Plain English words
 * like `get` or `merge` only count when written as code (`_.merge`, `get(`,
 * `` `merge` ``) or named as an API ("the template function"); distinctive
 * identifiers like `zipObjectDeep` match anywhere.
 */
export function mentionPattern(symbol: string): RegExp {
  const s = escapeRegExp(symbol);
  const distinctive = /[A-Z_$]/.test(symbol.slice(1));
  return new RegExp(
    distinctive ? `\\b${s}\\b` : `(\\.${s}\\b|\`${s}\\b|\\b${s}\\s*\\(|\\b${s}\\s+(function|method|option)s?\\b)`,
    "i",
  );
}

/** Flags usages whose API name appears in an advisory, e.g. `template` in "via `_.template`". */
function markMentions(usages: Usage[], vulns: Vulnerability[]): void {
  for (const u of usages) {
    if (u.symbol.startsWith("(") || u.symbol === "*" || u.symbol === "default" || u.symbol.length < 3) continue;
    const pattern = mentionPattern(u.symbol);
    u.mentionedBy = vulns.filter((v) => pattern.test(`${v.summary}\n${v.details}`)).map((v) => v.id);
  }
}

/** Semver treats every 0.x minor (and 0.0.x patch) bump as potentially breaking. */
export function isBreakingUpgrade(from: string, to: string): boolean {
  const a = semver.parse(from);
  const b = semver.parse(to);
  if (!a || !b) return true;
  if (a.major !== b.major) return true;
  if (a.major === 0 && a.minor !== b.minor) return true;
  return a.major === 0 && a.minor === 0 && a.patch !== b.patch;
}

export function maxSeverity(vulns: Vulnerability[]): number {
  return Math.max(0, ...vulns.map((v) => SEVERITY_RANK[v.severity?.toUpperCase() ?? ""] ?? 0));
}

export async function scan(projectDir: string, options: ScanOptions): Promise<Finding[]> {
  const deps = (await readNpmLockfile(projectDir)).filter((d) => options.includeDev || !d.dev);
  const osv = new OsvClient();
  const hits = await osv.queryBatch(deps.map((d) => ({ name: d.name, version: d.version })));

  // Vulnerabilities fixed by a verified backport for this exact version are not
  // reported again, but only while the patch is really applied.
  const manifest = await readManifest(projectDir);
  manifest.backports = await appliedBackports(projectDir, manifest);
  const vulnerable = deps.flatMap((dep, i) => {
    const mitigated = mitigatedIds(manifest, dep.name, dep.version);
    const ids = hits[i].filter((id) => !mitigated.has(id));
    return ids.length ? [{ dep, ids }] : [];
  });
  const usages = await findUsages(projectDir, [...new Set(vulnerable.map((v) => v.dep.name))]);

  const findings: Finding[] = [];
  for (const { dep, ids } of vulnerable) {
    const vulns = await osv.getVulns(ids, dep.name);
    const safeVersion = await osv.findSafeVersion(dep.name, dep.version, vulns);
    const depUsages = (usages.get(dep.name) ?? []).map((u) => ({ ...u }));
    markMentions(depUsages, vulns);
    const reachability: Reachability = depUsages.some((u) => u.mentionedBy.length)
      ? "likely"
      : depUsages.length
        ? "imported"
        : "not-imported";
    findings.push({
      dependency: dep,
      vulns,
      safeVersion,
      breaking: safeVersion !== undefined && isBreakingUpgrade(dep.version, safeVersion),
      usages: depUsages,
      reachability,
    });
  }

  return findings.sort(
    (a, b) =>
      REACH_RANK[b.reachability] - REACH_RANK[a.reachability] ||
      maxSeverity(b.vulns) - maxSeverity(a.vulns) ||
      a.dependency.name.localeCompare(b.dependency.name),
  );
}
