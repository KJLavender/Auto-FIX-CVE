import { cvesOf } from "./correlate.js";
import { endpoints } from "./endpoints.js";
import { loadJson } from "./http.js";
import type { Vulnerability } from "./types.js";

interface EpssResponse {
  data?: { cve: string; epss: string; percentile: string }[];
}

export interface Epss {
  /** Probability of exploitation activity in the next 30 days, 0–1. */
  score: number;
  /** Rank among all scored CVEs, 0–1. */
  percentile: number;
}

const BATCH = 100;
const cache = new Map<string, Epss | null>();

/**
 * FIRST's EPSS scores for the given CVEs. The source is the API (batched),
 * or a local file in the same JSON shape for offline use, or `off`. Missing
 * scores are simply absent; scanning never fails because of them.
 */
export async function loadEpss(cves: string[]): Promise<Map<string, Epss>> {
  const source = endpoints.epss();
  const wanted = [...new Set(cves)].filter((c) => !cache.has(c));
  if (source !== "off" && wanted.length) {
    const remote = /^https?:\/\//i.test(source);
    const batches = remote ? Array.from({ length: Math.ceil(wanted.length / BATCH) }, (_, i) => wanted.slice(i * BATCH, (i + 1) * BATCH)) : [wanted];
    for (const batch of batches) {
      const url = remote ? `${source}${source.includes("?") ? "&" : "?"}cve=${batch.join(",")}` : source;
      const doc = await loadJson<EpssResponse>(url);
      for (const d of doc?.data ?? []) {
        const score = Number(d.epss);
        if (Number.isFinite(score)) cache.set(d.cve.toUpperCase(), { score, percentile: Number(d.percentile) });
      }
    }
    for (const c of wanted) if (!cache.has(c)) cache.set(c, null);
  }
  const out = new Map<string, Epss>();
  for (const c of cves) {
    const hit = cache.get(c);
    if (hit) out.set(c, hit);
  }
  return out;
}

/** Test hook. */
export function resetEpss(): void {
  cache.clear();
}

/** Sets `epss` on each vulnerability: the highest score among the CVEs it is about. */
export async function markEpss(vulns: Vulnerability[]): Promise<void> {
  const scores = await loadEpss(vulns.flatMap((v) => cvesOf(v)));
  for (const v of vulns) {
    const best = cvesOf(v)
      .map((c) => scores.get(c))
      .filter((s): s is Epss => s !== undefined)
      .sort((a, b) => b.score - a.score)[0];
    if (best) v.epss = best;
  }
}

/** The highest EPSS score among vulnerabilities, 0 when none is scored. */
export function maxEpss(vulns: Vulnerability[]): number {
  return Math.max(0, ...vulns.map((v) => v.epss?.score ?? 0));
}

/** `EPSS 36%` for scores worth a reader's attention (1% and up), else empty. */
export function epssLabel(v: Vulnerability): string {
  const s = v.epss?.score;
  if (s === undefined || s < 0.01) return "";
  return `EPSS ${s >= 0.1 ? Math.round(s * 100) : (s * 100).toFixed(1)}%`;
}
