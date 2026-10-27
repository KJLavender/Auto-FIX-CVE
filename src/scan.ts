import { appliedBackports, mitigatedIds, readManifest, ruleActive } from "./backport/manifest.js";
import { findUsages } from "./impact/analyze.js";
import { findCsharpUsages } from "./impact/csharp.js";
import { loadKev, markExploited } from "./kev.js";
import { findGoUsages } from "./impact/go.js";
import { findPythonUsages } from "./impact/python.js";
import { findRustUsages } from "./impact/rust.js";
import { readLockfile, type LockRef } from "./lockfile/index.js";
import { dedupeVulns, OsvClient } from "./osv/client.js";
import type { Dependency, Finding, Reachability, Usage, Vulnerability } from "./types.js";
import { isBreakingUpgrade, normalizeName } from "./versions.js";

export interface ScanOptions {
  includeDev: boolean;
  /** Which lockfile to scan when the directory has several; defaults to the first found. */
  lock?: LockRef;
  /** Receives every vulnerability suppressed by an ignore rule. */
  ignored?: IgnoredVuln[];
  /** Leave out vulnerabilities rated below this (`low`, `moderate`, `high`, `critical`). Unrated ones are always kept. */
  minSeverity?: Severity;
}

export type Severity = "low" | "moderate" | "high" | "critical";
const MIN_RANK: Record<Severity, number> = { low: 1, moderate: 2, high: 3, critical: 4 };

/** Whether a vulnerability is rated at or above `min`. An unrated advisory is not assumed to be minor. */
export function meetsSeverity(v: Vulnerability, min: Severity | undefined): boolean {
  const rank = SEVERITY_RANK[v.severity?.toUpperCase() ?? ""] ?? 0;
  return !min || rank === 0 || rank >= MIN_RANK[min];
}

export interface IgnoredVuln {
  package: string;
  version: string;
  id: string;
  reason: string;
  until?: string;
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
export function markMentions(usages: Usage[], vulns: Vulnerability[]): void {
  for (const u of usages) {
    if (u.symbol.startsWith("(") || u.symbol === "*" || u.symbol === "default" || u.symbol.length < 3) continue;
    const pattern = mentionPattern(u.symbol);
    u.mentionedBy = vulns
      .filter((v) =>
        // Prefer the advisory's own list of vulnerable functions (`Type.Method` matches a call to `Method`).
        v.affectedSymbols?.length
          ? v.affectedSymbols.some((s) => s === u.symbol || s.split(/::|\./).pop() === u.symbol || u.symbol.endsWith(`::${s}`))
          : pattern.test(`${v.summary}\n${v.details}`),
      )
      .map((v) => v.id);
  }
}

export function maxSeverity(vulns: Vulnerability[]): number {
  return Math.max(0, ...vulns.map((v) => SEVERITY_RANK[v.severity?.toUpperCase() ?? ""] ?? 0));
}

export type FailOn = "any" | "likely" | "high" | "risk" | "none";

/** Whether the finding's code path is probably used: a definite model verdict wins over the name-matching heuristic. */
function reached(f: Finding): boolean {
  if (f.triage?.verdict === "reachable") return true;
  if (f.triage?.verdict === "not-reachable") return false;
  return f.reachability === "likely";
}

/** Whether a finding should fail `scan --fail-on <level>`. */
export function fails(f: Finding, failOn: FailOn): boolean {
  switch (failOn) {
    case "any":
      return true;
    case "likely":
      return reached(f);
    case "risk":
      // Attacked in the wild, or high/critical and reached by this code.
      return f.vulns.some((v) => v.knownExploited) || (reached(f) && maxSeverity(f.vulns) >= 3);
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
  const lock = await readLockfile(projectDir, options.lock);
  const finders = { npm: findUsages, PyPI: findPythonUsages, Go: findGoUsages, "crates.io": findRustUsages, NuGet: findCsharpUsages };
  const finder = finders[lock.deps[0]?.ecosystem ?? "npm"];
  return scanDependencies(lock.deps, projectDir, options, (wanted) => finder(projectDir, wanted));
}

/**
 * Matches dependencies against OSV and works out fixes and reachability.
 * `findUsages` maps package names to call sites; without source code (an SBOM) there are none.
 */
export async function scanDependencies(
  allDeps: Dependency[],
  projectDir: string,
  options: ScanOptions,
  findUsagesOf: (packages: string[]) => Promise<Map<string, Usage[]>> = async () => new Map(),
): Promise<Finding[]> {
  const deps = allDeps.filter((d) => options.includeDev || !d.dev);
  const osv = new OsvClient();
  const kev = loadKev();
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
  const usages = await findUsagesOf(wanted);

  const rules = (manifest.ignore ?? []).filter((r) => ruleActive(r));
  const resolved = await mapLimit(vulnerable, CONCURRENCY, async ({ dep, ids }): Promise<Finding | undefined> => {
    // Accepted risks are dropped before anything else, including the upgrade search.
    const accepted = new Set<string>();
    const vulns = dedupeVulns(await osv.getVulns(ids, dep.name, dep.ecosystem)).filter((v) => {
      const keys = [v.id, ...v.aliases];
      const rule = rules.find((r) => keys.includes(r.id) && (!r.package || normalizeName(dep.ecosystem, r.package) === dep.name));
      if (!rule) {
        return meetsSeverity(v, options.minSeverity);
      }
      keys.forEach((k) => accepted.add(k));
      options.ignored?.push({ package: dep.name, version: dep.version, id: v.id, reason: rule.reason, until: rule.until });
      return false;
    });
    if (vulns.length === 0) return undefined;
    markExploited(vulns, await kev);
    const safe = await osv.findSafeVersion(dep.name, dep.version, vulns, dep.ecosystem, accepted);
    const safeVersion = safe.version;
    // The search may name a duplicate record; report each unfixable vulnerability once, by its primary id.
    const unfixableIds = new Set(safe.unfixable);
    const unfixable = vulns.filter((v) => [v.id, ...v.aliases].some((k) => unfixableIds.has(k))).map((v) => v.id);
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

  const findings = resolved.filter((f): f is Finding => f !== undefined);
  return findings.sort(
    (a, b) =>
      Number(b.vulns.some((v) => v.knownExploited)) - Number(a.vulns.some((v) => v.knownExploited)) ||
      REACH_RANK[b.reachability] - REACH_RANK[a.reachability] ||
      maxSeverity(b.vulns) - maxSeverity(a.vulns) ||
      a.dependency.name.localeCompare(b.dependency.name),
  );
}
