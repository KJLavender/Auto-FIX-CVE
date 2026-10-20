import { appliedBackports, mitigatedIds, readManifest } from "./backport/manifest.js";
import { findUsages } from "./impact/analyze.js";
import { findPythonUsages } from "./impact/python.js";
import { readLockfile } from "./lockfile/index.js";
import { OsvClient } from "./osv/client.js";
import type { Finding, Reachability, Usage, Vulnerability } from "./types.js";
import { isBreakingUpgrade } from "./versions.js";

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

export function maxSeverity(vulns: Vulnerability[]): number {
  return Math.max(0, ...vulns.map((v) => SEVERITY_RANK[v.severity?.toUpperCase() ?? ""] ?? 0));
}

export type FailOn = "any" | "likely" | "high" | "none";

/** Whether a finding should fail `scan --fail-on <level>`. */
export function fails(f: Finding, failOn: FailOn): boolean {
  switch (failOn) {
    case "any":
      return true;
    case "likely":
      // A definite model verdict overrides the name-matching heuristic; "unclear" falls back to it.
      if (f.triage?.verdict === "reachable") return true;
      if (f.triage?.verdict === "not-reachable") return false;
      return f.reachability === "likely";
    case "high":
      return maxSeverity(f.vulns) >= 3;
    case "none":
      return false;
  }
}

const CONCURRENCY = 8;

/** Like Promise.all over `items`, with at most `limit` calls in flight; keeps input order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

export async function scan(projectDir: string, options: ScanOptions): Promise<Finding[]> {
  const lock = await readLockfile(projectDir);
  const deps = lock.deps.filter((d) => options.includeDev || !d.dev);
  const osv = new OsvClient();
  const hits = await osv.queryBatch(deps.map((d) => ({ name: d.name, version: d.version, ecosystem: d.ecosystem })));

  // Vulnerabilities fixed by a verified backport for this exact version are not
  // reported again, but only while the patch is really applied.
  const manifest = await readManifest(projectDir);
  manifest.backports = await appliedBackports(projectDir, manifest);
  const vulnerable = deps.flatMap((dep, i) => {
    const mitigated = mitigatedIds(manifest, dep.name, dep.version);
    const ids = hits[i].filter((id) => !mitigated.has(id));
    return ids.length ? [{ dep, ids }] : [];
  });
  // Also look up the direct dependencies that pull in transitive ones: calling
  // axios is how an app reaches a vulnerable follow-redirects underneath it.
  const introducers = vulnerable.flatMap((v) => (v.dep.direct ? [] : v.dep.introducedBy));
  const wanted = [...new Set([...vulnerable.map((v) => v.dep.name), ...introducers])];
  const usages = lock.deps[0]?.ecosystem === "PyPI" ? await findPythonUsages(projectDir, wanted) : await findUsages(projectDir, wanted);

  const findings = await mapLimit(vulnerable, CONCURRENCY, async ({ dep, ids }): Promise<Finding> => {
    const vulns = await osv.getVulns(ids, dep.name, dep.ecosystem);
    const { version: safeVersion, unfixable } = await osv.findSafeVersion(dep.name, dep.version, vulns, dep.ecosystem);
    const depUsages = (usages.get(dep.name) ?? []).map((u) => ({ ...u }));
    markMentions(depUsages, vulns);
    const via = dep.direct
      ? []
      : dep.introducedBy
          .filter((p) => p !== dep.name && usages.get(p)?.length)
          .map((p) => ({ package: p, usages: usages.get(p)! }));
    const reachability: Reachability = depUsages.some((u) => u.mentionedBy.length)
      ? "likely"
      : depUsages.length || via.length
        ? "imported"
        : "not-imported";
    return {
      dependency: dep,
      vulns,
      safeVersion,
      unfixable,
      breaking: safeVersion !== undefined && isBreakingUpgrade(dep.ecosystem, dep.version, safeVersion),
      usages: depUsages,
      via,
      reachability,
    };
  });

  return findings.sort(
    (a, b) =>
      REACH_RANK[b.reachability] - REACH_RANK[a.reachability] ||
      maxSeverity(b.vulns) - maxSeverity(a.vulns) ||
      a.dependency.name.localeCompare(b.dependency.name),
  );
}
