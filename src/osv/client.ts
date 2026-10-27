import { fetchWithRetry } from "../http.js";
import { registryUsableVersions, type UsableVersions } from "../registry.js";
import type { Vulnerability } from "../types.js";
import { compareVersions, isValidVersion, normalizeName, type Ecosystem } from "../versions.js";

import { endpoints } from "../endpoints.js";
const BATCH_SIZE = 1000;
const CONCURRENCY = 8;

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  references?: { type: string; url: string }[];
  affected?: {
    package?: { name: string; ecosystem: string };
    ranges?: { type: string; events: { introduced?: string; fixed?: string }[] }[];
    // Go advisories name the exact vulnerable functions; RustSec ones list `crate::path::fn`.
    ecosystem_specific?: { imports?: { path: string; symbols?: string[] }[]; affects?: { functions?: string[] } };
  }[];
}

export interface SafeVersion {
  /** Smallest upgrade that fixes everything fixable; undefined if nothing can be fixed by upgrading. */
  version?: string;
  /** Vulnerabilities with no fixed release, which an upgrade cannot address. */
  unfixable: string[];
}

export interface PackageQuery {
  name: string;
  version: string;
  ecosystem?: Ecosystem;
}

// OSV tags most fix links as WEB rather than FIX, so match on URL shape instead.
const FIX_URL = /github\.com\/[^/]+\/[^/]+\/(commit\/[0-9a-f]{7,40}|pull\/\d+)/i;
// Edits to advisory databases look like fix PRs but contain no code fix.
const ADVISORY_DB = /github\.com\/(github\/advisory-database|advisories)\//i;

export class OsvClient {
  private vulnCache = new Map<string, Promise<OsvVuln>>();

  /** `usable` reports installable versions, so a yanked or deprecated release is never suggested. */
  constructor(private readonly usable: UsableVersions = registryUsableVersions) {}

  /** Returns the vulnerability ids affecting each query, in the same order. */
  async queryBatch(queries: PackageQuery[]): Promise<string[][]> {
    const out: string[][] = [];
    for (let i = 0; i < queries.length; i += BATCH_SIZE) {
      const chunk = queries.slice(i, i + BATCH_SIZE);
      const res = await fetchWithRetry(`${endpoints.osv()}/querybatch`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          queries: chunk.map((q) => ({ package: { name: q.name, ecosystem: q.ecosystem ?? "npm" }, version: q.version })),
        }),
      });
      if (!res.ok) throw new Error(`OSV querybatch failed: ${res.status} ${await res.text()}`);
      const body = (await res.json()) as { results: { vulns?: { id: string }[] }[] };
      for (const r of body.results) out.push((r.vulns ?? []).map((v) => v.id));
    }
    return out;
  }

  /**
   * The smallest installable version at or above `candidate`: a fixed release
   * may have been yanked (cargo refuses those) or deprecated since. Unknown
   * registry data leaves the candidate unchanged.
   */
  private async installable(name: string, ecosystem: Ecosystem, candidate: string): Promise<string> {
    const usable = await this.usable(ecosystem, name);
    if (!usable || usable.has(candidate)) return candidate;
    const next = [...usable]
      .filter((v) => isValidVersion(ecosystem, v) && compareVersions(ecosystem, v, candidate) > 0)
      .filter((v) => !/-|[a-z]/i.test(v.replace(/^v/, ""))) // skip pre-releases
      .sort((a, b) => compareVersions(ecosystem, a, b))[0];
    return next ?? candidate;
  }

  private fetchVuln(id: string): Promise<OsvVuln> {
    let cached = this.vulnCache.get(id);
    if (!cached) {
      cached = fetchWithRetry(`${endpoints.osv()}/vulns/${encodeURIComponent(id)}`).then(async (res) => {
        if (!res.ok) throw new Error(`OSV vulns/${id} failed: ${res.status}`);
        return (await res.json()) as OsvVuln;
      });
      this.vulnCache.set(id, cached);
    }
    return cached;
  }

  async getVulns(ids: string[], packageName: string, ecosystem: Ecosystem = "npm"): Promise<Vulnerability[]> {
    const results: Vulnerability[] = [];
    for (let i = 0; i < ids.length; i += CONCURRENCY) {
      const raw = await Promise.all(ids.slice(i, i + CONCURRENCY).map((id) => this.fetchVuln(id)));
      results.push(...raw.map((v) => toVulnerability(v, packageName, ecosystem)));
    }
    return results;
  }

  /**
   * Finds the smallest version above `current` that fixes every vulnerability
   * that has a fix: start from the fixes for the current vulns, then re-query
   * OSV so an upgrade never lands on a version vulnerable to something else.
   * Vulnerabilities with no fix anywhere are returned as `unfixable` instead of
   * blocking the fixes that do exist.
   */
  async findSafeVersion(
    name: string,
    current: string,
    vulns: Vulnerability[],
    ecosystem: Ecosystem = "npm",
    /** Ids (and aliases) of accepted risks that should not drive the upgrade. */
    accepted: Set<string> = new Set(),
  ): Promise<SafeVersion> {
    const unfixable = new Set<string>();
    let candidate = current;
    let pending = vulns;
    for (let attempt = 0; attempt < 10; attempt++) {
      const base = candidate;
      for (const v of pending) {
        const fix = minimalFixAbove(ecosystem, v.fixedVersions, base);
        if (!fix) unfixable.add(v.id);
        else if (compareVersions(ecosystem, fix, candidate) > 0) candidate = fix;
      }
      if (candidate === current) return { unfixable: [...unfixable] };
      candidate = await this.installable(name, ecosystem, candidate);
      const [ids] = await this.queryBatch([{ name, version: candidate, ecosystem }]);
      const remaining = ids.filter((id) => !unfixable.has(id) && !accepted.has(id));
      if (remaining.length === 0) return { version: candidate, unfixable: [...unfixable] };
      pending = await this.getVulns(remaining, name, ecosystem);
    }
    return { unfixable: [...unfixable] };
  }
}

/**
 * OSV often returns one vulnerability under several ids (e.g. a GHSA and a
 * PYSEC record for the same CVE, each listing the other as an alias). Merge
 * records that share any id or alias, preferring the GHSA as the primary id.
 */
export function dedupeVulns(vulns: Vulnerability[]): Vulnerability[] {
  const groups: Vulnerability[][] = [];
  const groupOf = new Map<string, Vulnerability[]>();
  for (const v of vulns) {
    const keys = [v.id, ...v.aliases];
    const hits = [...new Set(keys.map((k) => groupOf.get(k)).filter((g): g is Vulnerability[] => g !== undefined))];
    const group = hits[0] ?? [];
    if (!hits.length) groups.push(group);
    for (const other of hits.slice(1)) {
      group.push(...other);
      groups.splice(groups.indexOf(other), 1);
    }
    group.push(v);
    for (const member of group) for (const k of [member.id, ...member.aliases]) groupOf.set(k, group);
  }
  return groups.map((group) => {
    const primary = group.find((v) => v.id.startsWith("GHSA-")) ?? group[0];
    const ids = new Set(group.flatMap((v) => [v.id, ...v.aliases]));
    ids.delete(primary.id);
    return {
      ...primary,
      aliases: [...ids],
      severity: primary.severity ?? group.find((v) => v.severity)?.severity,
      details: group.map((v) => v.details).sort((a, b) => b.length - a.length)[0],
      fixedVersions: [...new Set(group.flatMap((v) => v.fixedVersions))],
      fixCommits: [...new Set(group.flatMap((v) => v.fixCommits))],
      affectedSymbols: [...new Set(group.flatMap((v) => v.affectedSymbols ?? []))],
    };
  });
}

function minimalFixAbove(eco: Ecosystem, fixed: string[], version: string): string | undefined {
  return fixed
    .filter((f) => isValidVersion(eco, f) && compareVersions(eco, f, version) > 0)
    .sort((a, b) => compareVersions(eco, a, b))[0];
}

function toVulnerability(v: OsvVuln, packageName: string, ecosystem: Ecosystem): Vulnerability {
  // NuGet ids are case-insensitive.
  const same = (name: string) =>
    ecosystem === "NuGet" ? name.toLowerCase() === packageName.toLowerCase() : normalizeName(ecosystem, name) === normalizeName(ecosystem, packageName);
  const fixedVersions = new Set<string>();
  const symbols = new Set<string>();
  for (const a of v.affected ?? []) {
    if (a.package?.ecosystem !== ecosystem || !same(a.package.name)) continue;
    for (const r of a.ranges ?? []) {
      // OSV writes Go versions without the `v` that go.mod and `go get` use.
      for (const e of r.events) if (e.fixed) fixedVersions.add(ecosystem === "Go" && !e.fixed.startsWith("v") ? `v${e.fixed}` : e.fixed);
    }
    for (const imp of a.ecosystem_specific?.imports ?? []) for (const sym of imp.symbols ?? []) symbols.add(sym);
    for (const fn of a.ecosystem_specific?.affects?.functions ?? []) symbols.add(fn.split("::").slice(1).join("::"));
  }
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary ?? "",
    details: v.details ?? "",
    severity: v.database_specific?.severity,
    fixedVersions: [...fixedVersions],
    affectedSymbols: [...symbols],
    fixCommits: [
      ...new Set((v.references ?? []).map((r) => r.url).filter((u) => FIX_URL.test(u) && !ADVISORY_DB.test(u))),
    ],
  };
}
