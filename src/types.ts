import type { Ecosystem } from "./versions.js";

export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** Install locations in the lockfile, e.g. `node_modules/a/node_modules/b`. */
  paths: string[];
  /** Declared directly in the root package.json. */
  direct: boolean;
  /** Only installed as a dev dependency. */
  dev: boolean;
  /** Direct dependencies that pull this package in (itself, if direct). */
  introducedBy: string[];
  /**
   * Debian: advisories are about the source package (`brotli`), but images
   * install binary packages built from it (`libbrotli1`); these are the ones present.
   */
  binaries?: { name: string; version: string }[];
}

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  details: string;
  severity?: string;
  /** Versions that fix this vulnerability for the affected package. */
  fixedVersions: string[];
  /** Upstream commit / pull request URLs that contain the fix. */
  fixCommits: string[];
  /** Vulnerable functions named by the advisory (Go advisories list them), e.g. `Default` or `Context.File`. */
  affectedSymbols?: string[];
  /** Listed in CISA's Known Exploited Vulnerabilities catalog: attacked in the wild. */
  knownExploited?: boolean;
  /**
   * Upstream ids a downstream record is about, e.g. the CVEs a Debian DSA fixes.
   * Not aliases (one DSA covers several CVEs), so records are not merged on them.
   */
  upstream?: string[];
  /** FIRST EPSS: probability of exploitation in the next 30 days, and its percentile. */
  epss?: { score: number; percentile: number };
}

export interface Usage {
  file: string;
  line: number;
  column: number;
  /** Module specifier as written in the source, e.g. `lodash/fp`. */
  specifier: string;
  /** The API being used, e.g. `template` for `_.template(...)`. */
  symbol: string;
  snippet: string;
  /** Vulnerability ids whose advisory text mentions this symbol. */
  mentionedBy: string[];
}

export interface ViaUsage {
  /** Direct dependency that pulls in the vulnerable package. */
  package: string;
  /** Where the project uses that direct dependency. */
  usages: Usage[];
}

export type Reachability = "likely" | "imported" | "not-imported";

/** The model's judgement of whether the project's usage can trigger the vulnerabilities. */
export interface Triage {
  verdict: "reachable" | "not-reachable" | "unclear";
  reasoning: string;
  conditions: string;
}

export interface Finding {
  dependency: Dependency;
  vulns: Vulnerability[];
  /** Smallest version that OSV reports as free of every vulnerability that has a fix. */
  safeVersion?: string;
  /** Vulnerability ids with no fixed release: upgrading cannot address them. */
  unfixable: string[];
  /** True when upgrading to the safe version is a semver-breaking change. */
  breaking: boolean;
  usages: Usage[];
  /** For transitive packages: the used direct dependencies that pull them in. */
  via: ViaUsage[];
  reachability: Reachability;
  /** Set by `scan --triage`. */
  triage?: Triage;
}
