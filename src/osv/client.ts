import { fetchWithRetry } from "../http.js";
import type { Vulnerability } from "../types.js";
import { compareVersions, isValidVersion, normalizeName, type Ecosystem } from "../versions.js";

const OSV_API = "https://api.osv.dev/v1";
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

  /** Returns the vulnerability ids affecting each query, in the same order. */
  async queryBatch(queries: PackageQuery[]): Promise<string[][]> {
    const out: string[][] = [];
    for (let i = 0; i < queries.length; i += BATCH_SIZE) {
      const chunk = queries.slice(i, i + BATCH_SIZE);
      const res = await fetchWithRetry(`${OSV_API}/querybatch`, {
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

  private fetchVuln(id: string): Promise<OsvVuln> {
    let cached = this.vulnCache.get(id);
    if (!cached) {
      cached = fetchWithRetry(`${OSV_API}/vulns/${encodeURIComponent(id)}`).then(async (res) => {
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
      const [ids] = await this.queryBatch([{ name, version: candidate, ecosystem }]);
      const remaining = ids.filter((id) => !unfixable.has(id));
      if (remaining.length === 0) return { version: candidate, unfixable: [...unfixable] };
      pending = await this.getVulns(remaining, name, ecosystem);
    }
    return { unfixable: [...unfixable] };
  }
}

function minimalFixAbove(eco: Ecosystem, fixed: string[], version: string): string | undefined {
  return fixed
    .filter((f) => isValidVersion(eco, f) && compareVersions(eco, f, version) > 0)
    .sort((a, b) => compareVersions(eco, a, b))[0];
}

function toVulnerability(v: OsvVuln, packageName: string, ecosystem: Ecosystem): Vulnerability {
  const wanted = normalizeName(ecosystem, packageName);
  const fixedVersions = new Set<string>();
  for (const a of v.affected ?? []) {
    if (a.package?.ecosystem !== ecosystem || normalizeName(ecosystem, a.package.name) !== wanted) continue;
    for (const r of a.ranges ?? []) {
      for (const e of r.events) if (e.fixed) fixedVersions.add(e.fixed);
    }
  }
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary ?? "",
    details: v.details ?? "",
    severity: v.database_specific?.severity,
    fixedVersions: [...fixedVersions],
    fixCommits: [
      ...new Set((v.references ?? []).map((r) => r.url).filter((u) => FIX_URL.test(u) && !ADVISORY_DB.test(u))),
    ],
  };
}
