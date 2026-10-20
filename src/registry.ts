import { fetchWithRetry } from "./http.js";
import type { Ecosystem } from "./versions.js";

/** Versions that can actually be installed: not yanked (PyPI, crates.io) and not deprecated (npm). */
export type UsableVersions = (eco: Ecosystem, name: string) => Promise<Set<string> | undefined>;

async function json(url: string, headers: Record<string, string> = {}): Promise<unknown> {
  const res = await fetchWithRetry(url, { headers: { "user-agent": "autofix-cve", ...headers } }).catch(() => undefined);
  return res?.ok ? res.json() : undefined;
}

async function npmUsable(name: string): Promise<Set<string> | undefined> {
  // The abbreviated document is much smaller than the full one and still has `deprecated`.
  const doc = (await json(`https://registry.npmjs.org/${name.replace("/", "%2f")}`, {
    accept: "application/vnd.npm.install-v1+json",
  })) as { versions?: Record<string, { deprecated?: string }> } | undefined;
  if (!doc?.versions) return undefined;
  return new Set(Object.entries(doc.versions).filter(([, v]) => !v.deprecated).map(([k]) => k));
}

async function pypiUsable(name: string): Promise<Set<string> | undefined> {
  const doc = (await json(`https://pypi.org/pypi/${name}/json`)) as { releases?: Record<string, { yanked?: boolean }[]> } | undefined;
  if (!doc?.releases) return undefined;
  return new Set(Object.entries(doc.releases).filter(([, files]) => files.length && !files.every((f) => f.yanked)).map(([k]) => k));
}

/** crates.io sparse index path: 1/a, 2/ab, 3/a/abc, ab/cd/abcd… */
export function cratesIndexPath(name: string): string {
  const n = name.toLowerCase();
  if (n.length <= 2) return `${n.length}/${n}`;
  if (n.length === 3) return `3/${n[0]}/${n}`;
  return `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

async function cratesUsable(name: string): Promise<Set<string> | undefined> {
  const res = await fetchWithRetry(`https://index.crates.io/${cratesIndexPath(name)}`, { headers: { "user-agent": "autofix-cve" } }).catch(
    () => undefined,
  );
  if (!res?.ok) return undefined;
  const usable = new Set<string>();
  for (const line of (await res.text()).split("\n")) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line) as { vers?: string; yanked?: boolean };
      if (entry.vers && !entry.yanked) usable.add(entry.vers);
    } catch {
      return undefined;
    }
  }
  return usable;
}

const cache = new Map<string, Promise<Set<string> | undefined>>();

/** Looks up installable versions in the package's registry; undefined when unknown (e.g. Go, or offline). */
export const registryUsableVersions: UsableVersions = (eco, name) => {
  const key = `${eco}:${name}`;
  let hit = cache.get(key);
  if (!hit) {
    hit = (eco === "npm" ? npmUsable(name) : eco === "PyPI" ? pypiUsable(name) : eco === "crates.io" ? cratesUsable(name) : Promise.resolve(undefined)).catch(
      () => undefined,
    );
    cache.set(key, hit);
  }
  return hit;
};
