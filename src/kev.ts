import { readFile } from "node:fs/promises";
import { endpoints } from "./endpoints.js";
import { fetchWithRetry } from "./http.js";
import type { Vulnerability } from "./types.js";

interface KevCatalog {
  vulnerabilities?: { cveID?: string }[];
}

let catalog: Promise<Set<string> | undefined> | undefined;

/**
 * CVE ids from CISA's Known Exploited Vulnerabilities catalog, i.e. ones seen
 * attacked in the wild. Undefined when it is turned off or cannot be loaded;
 * scanning then goes on without it rather than failing.
 */
export function loadKev(): Promise<Set<string> | undefined> {
  catalog ??= (async () => {
    const source = endpoints.kev();
    if (source === "off") return undefined;
    const text = /^https?:\/\//i.test(source)
      ? await fetchWithRetry(source, { headers: { "user-agent": "autofix-cve" } }).then((r) => (r.ok ? r.text() : undefined))
      : await readFile(source, "utf8");
    if (!text) return undefined;
    const ids = (JSON.parse(text) as KevCatalog).vulnerabilities?.flatMap((v) => (v.cveID ? [v.cveID.toUpperCase()] : []));
    return ids?.length ? new Set(ids) : undefined;
  })().catch(() => undefined);
  return catalog;
}

/** Test hook: forget the loaded catalog. */
export function resetKev(): void {
  catalog = undefined;
}

/** Sets `knownExploited` on vulnerabilities listed in the catalog under any of their ids. */
export function markExploited(vulns: Vulnerability[], kev: Set<string> | undefined): void {
  if (!kev) return;
  for (const v of vulns) {
    if ([v.id, ...v.aliases, ...(v.upstream ?? [])].some((id) => kev.has(id.toUpperCase()))) v.knownExploited = true;
  }
}
