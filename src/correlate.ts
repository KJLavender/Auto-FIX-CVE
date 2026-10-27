import pc from "picocolors";
import type { Vulnerability } from "./types.js";

/** One place a vulnerability shows up: a package in a lockfile or SBOM, or a runtime in a Dockerfile. */
export interface Exposure {
  /** Where it was found, e.g. `api-server/package-lock.json` or `backend/Dockerfile:3`. */
  where: string;
  /** What is affected, e.g. `Node.js 22.20.0` or `brotli 1.0.9-2 (libbrotli1)`. */
  component: string;
  /** The change that fixes it, when known. */
  fix?: string;
  vulns: Vulnerability[];
  /** Ids the fix does not cover (no fixed release yet). */
  unfixable?: string[];
}

export interface UpstreamGroup {
  cve: string;
  summary: string;
  knownExploited: boolean;
  places: { where: string; component: string; fix?: string; id: string }[];
}

/** CVE ids a record is about: its id, aliases and upstream ids (`DEBIAN-CVE-2026-1` counts as `CVE-2026-1`). */
export function cvesOf(v: Pick<Vulnerability, "id" | "aliases" | "upstream">): string[] {
  const ids = [v.id, ...v.aliases, ...(v.upstream ?? [])].map((id) => id.replace(/^[A-Z]+-(?=CVE-)/, ""));
  return [...new Set(ids.filter((id) => /^CVE-\d+-\d+$/.test(id)))];
}

/**
 * Groups vulnerabilities by CVE across every place they were found, keeping
 * the ones that span more than one component: the same upstream bug bundled
 * into several runtimes and packages (Brotli in Node.js, .NET and Debian's
 * libbrotli), each needing its own fix.
 */
export function correlate(exposures: Exposure[]): UpstreamGroup[] {
  const groups = new Map<string, UpstreamGroup>();
  for (const e of exposures) {
    for (const v of e.vulns) {
      for (const cve of cvesOf(v)) {
        const g = groups.get(cve) ?? { cve, summary: "", knownExploited: false, places: [] };
        g.knownExploited ||= Boolean(v.knownExploited);
        if (!g.summary && v.summary && !/^Fixed in /.test(v.summary)) g.summary = v.summary;
        if (!g.places.some((p) => p.where === e.where && p.component === e.component)) {
          g.places.push({ where: e.where, component: e.component, fix: e.unfixable?.includes(v.id) ? undefined : e.fix, id: v.id });
        }
        groups.set(cve, g);
      }
    }
  }
  const spread = (g: UpstreamGroup) => new Set(g.places.map((p) => p.component.split(" ")[0])).size;
  return [...groups.values()]
    .filter((g) => spread(g) > 1)
    .sort(
      (a, b) =>
        Number(b.knownExploited) - Number(a.knownExploited) ||
        spread(b) - spread(a) ||
        b.cve.localeCompare(a.cve, undefined, { numeric: true }),
    );
}

export function formatUpstreamGroups(groups: UpstreamGroup[]): string {
  if (!groups.length) return pc.dim("No vulnerability appears in more than one component.");
  const out: string[] = [pc.bold(`The same vulnerability in several components (${groups.length})`), ""];
  for (const g of groups) {
    const kev = g.knownExploited ? ` ${pc.bgRed(pc.white(" KNOWN EXPLOITED "))}` : "";
    out.push(`${pc.bold(g.cve)}${kev}  ${pc.dim(g.summary)}`);
    const width = Math.max(...g.places.map((p) => p.component.length));
    for (const p of g.places) {
      out.push(`  ${p.component.padEnd(width)}  ${pc.dim(p.where)}${p.fix ? `  ${pc.green(`→ ${p.fix}`)}` : `  ${pc.red("no fix yet")}`}`);
    }
    out.push("");
  }
  return out.join("\n");
}
