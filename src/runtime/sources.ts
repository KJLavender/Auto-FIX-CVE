import semver from "semver";
import { endpoints } from "../endpoints.js";
import { loadJson } from "../http.js";
import type { Vulnerability } from "../types.js";

/** What a base image tag means for the runtime inside it. */
export interface RuntimeStatus {
  runtime: "Node.js" | ".NET";
  /** Release line: `22` for Node.js, `8.0` for .NET. */
  line: string;
  /** The exact version, when the tag pins one; floating tags (`22-slim`, `8.0`) do not. */
  version?: string;
  /** Newest release of the line, and its date. */
  latest?: string;
  latestDate?: string;
  /** Vulnerabilities fixed in releases after `version`. */
  vulns: Vulnerability[];
  /** End of support for the line (YYYY-MM-DD), when known. */
  eol?: string;
  /** The same tag pinned to `latest`, keeping its variant, e.g. `22.23.4-bookworm-slim`. */
  pinnedTag?: string;
}

export interface RuntimeSource {
  matches(repository: string): boolean;
  check(repository: string, tag: string | undefined): Promise<RuntimeStatus | undefined>;
}

/** `22.20.0-bookworm-slim` → version parts and the variant suffix. */
export function splitTag(tag: string): { parts: number[]; suffix: string } | undefined {
  const m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(-.*)?$/.exec(tag);
  if (!m) return undefined;
  return { parts: [m[1], m[2], m[3]].filter((p) => p !== undefined).map(Number), suffix: m[4] ?? "" };
}

const once = <T>(load: () => Promise<T>) => {
  let p: Promise<T> | undefined;
  return () => (p ??= load());
};

// ---------- Node.js ----------

interface NodeRelease {
  version: string; // "v22.23.4"
  date: string;
  security: boolean;
  lts: string | false;
}

interface NodeVuln {
  cve: string[];
  vulnerable: string;
  patched: string;
  description?: string;
  overview?: string;
  severity?: string;
  ref?: string;
}

const NODE_SEVERITY: Record<string, string> = { critical: "CRITICAL", high: "HIGH", medium: "MODERATE", low: "LOW" };

const nodeReleases = once(() => loadJson<NodeRelease[]>(endpoints.nodeReleases()));
const nodeVulns = once(() => loadJson<Record<string, NodeVuln>>(endpoints.nodeVulns()));
const nodeSchedule = once(() => loadJson<Record<string, { end?: string }>>(endpoints.nodeSchedule()));

function satisfies(version: string, range: string): boolean {
  try {
    return semver.satisfies(version, range);
  } catch {
    return false;
  }
}

export const nodeSource: RuntimeSource = {
  matches: (repository) => repository.split("/").pop() === "node",

  async check(_repository, tag) {
    const releases = await nodeReleases();
    if (!releases?.length) return undefined;
    const t = tag ?? "latest";
    const split = splitTag(t);
    let major: number;
    let suffix: string;
    if (split) {
      major = split.parts[0];
      suffix = split.suffix;
    } else {
      // Named tags: `lts`, `lts-slim`, `current`, `latest`, or a bare variant like `alpine`.
      const lts = /^lts(-.*)?$/.exec(t);
      const named = /^(?:current|latest)(-.*)?$/.exec(t);
      const pick = lts ? releases.find((r) => r.lts) : releases[0];
      if (!pick) return undefined;
      major = semver.major(pick.version);
      suffix = lts ? (lts[1] ?? "") : named ? (named[1] ?? "") : `-${t}`;
    }
    const line = releases.filter((r) => semver.major(r.version) === major);
    if (!line.length) return undefined;
    const latest = line[0];
    const version = split?.parts.length === 3 ? split.parts.join(".") : undefined;

    const vulns: Vulnerability[] = [];
    if (version) {
      const index = (await nodeVulns()) ?? {};
      for (const [key, v] of Object.entries(index)) {
        if (!satisfies(version, v.vulnerable) || satisfies(version, v.patched)) continue;
        const fixed = v.patched
          .split("||")
          .map((r) => r.trim().replace(/^[\^~>=\s]+/, ""))
          .filter((r) => semver.valid(r) && semver.major(r) === major);
        vulns.push({
          id: `NSWG-CORE-${key}`,
          aliases: v.cve,
          summary: v.description ?? "",
          details: v.overview ?? "",
          severity: NODE_SEVERITY[v.severity ?? ""],
          fixedVersions: fixed,
          fixCommits: [],
        });
      }
      // The advisory index can trail a security release by weeks; report releases it does not cover yet.
      const covered = new Set(vulns.flatMap((v) => v.fixedVersions));
      for (const r of line) {
        const rv = r.version.slice(1);
        if (!r.security || !semver.gt(rv, version) || covered.has(rv)) continue;
        vulns.push({
          id: `NODE-SECURITY-${rv}`,
          aliases: [],
          summary: `Node.js ${rv} (${r.date}) is a security release whose fixes are not in the advisory index yet`,
          details: `See https://nodejs.org/en/blog/release/v${rv}`,
          fixedVersions: [rv],
          fixCommits: [],
        });
      }
    }
    const eol = (await nodeSchedule())?.[`v${major}`]?.end;
    return {
      runtime: "Node.js",
      line: String(major),
      version,
      latest: latest.version.slice(1),
      latestDate: latest.date,
      vulns,
      eol,
      pinnedTag: `${latest.version.slice(1)}${suffix}`,
    };
  },
};

// ---------- .NET ----------

interface DotnetRelease {
  "release-version": string;
  "release-date": string;
  security: boolean;
  "cve-list"?: { "cve-id": string; "cve-url"?: string }[] | null;
  runtime?: { version: string };
  sdks?: { version: string }[];
  sdk?: { version: string };
}

interface DotnetChannel {
  "eol-date"?: string;
  releases: DotnetRelease[];
}

const dotnetChannels = new Map<string, Promise<DotnetChannel | undefined>>();
function dotnetChannel(channel: string): Promise<DotnetChannel | undefined> {
  let p = dotnetChannels.get(channel);
  if (!p) dotnetChannels.set(channel, (p = loadJson<DotnetChannel>(endpoints.dotnetReleases(channel))));
  return p;
}

const DOTNET_IMAGE = /(^|\/)dotnet\/(aspnet|runtime|runtime-deps|sdk)$/;

export const dotnetSource: RuntimeSource = {
  matches: (repository) => DOTNET_IMAGE.test(repository),

  async check(repository, tag) {
    const split = tag ? splitTag(tag) : undefined;
    if (!split || split.parts.length < 2) return undefined;
    const channel = `${split.parts[0]}.${split.parts[1]}`;
    const data = await dotnetChannel(channel);
    const releases = data?.releases ?? [];
    if (!releases.length) return undefined;
    const sdk = repository.endsWith("/sdk");
    const latest = releases[0];

    // Runtime images are tagged by runtime version (8.0.11); SDK images by SDK version (8.0.404).
    let index = -1;
    let version: string | undefined;
    let pinned: string;
    if (split.parts.length === 3) {
      version = split.parts.join(".");
      index = releases.findIndex((r) => (sdk ? (r.sdks ?? []).some((s) => s.version === version) : r["release-version"] === version));
    }
    if (sdk) {
      // Stay in the same feature band (8.0.4xx), which is what a pinned SDK tag selects.
      const band = version ? Math.floor(split.parts[2] / 100) : undefined;
      const inBand = (v: string) => band === undefined || Math.floor(Number(v.split(".")[2]) / 100) === band;
      const newest = releases.flatMap((r) => (r.sdks ?? []).map((s) => s.version)).find(inBand);
      pinned = newest ?? latest.sdk?.version ?? latest["release-version"];
    } else {
      pinned = latest["release-version"];
    }

    const vulns: Vulnerability[] = [];
    if (index > 0) {
      const seen = new Map<string, Vulnerability>();
      // Oldest first, so each CVE records the first release that fixes it.
      for (const r of releases.slice(0, index).reverse()) {
        if (!r.security) continue;
        for (const c of r["cve-list"] ?? []) {
          if (seen.has(c["cve-id"])) continue;
          seen.set(c["cve-id"], {
            id: c["cve-id"],
            aliases: [c["cve-id"]],
            summary: `Fixed in .NET ${r["release-version"]} (${r["release-date"]})`,
            details: c["cve-url"] ?? "",
            fixedVersions: [r["release-version"]],
            fixCommits: [],
          });
        }
      }
      vulns.push(...seen.values());
    }
    return {
      runtime: ".NET",
      line: channel,
      version,
      latest: latest["release-version"],
      latestDate: latest["release-date"],
      vulns,
      eol: data?.["eol-date"],
      pinnedTag: `${pinned}${split.suffix}`,
    };
  },
};

export const RUNTIME_SOURCES: RuntimeSource[] = [nodeSource, dotnetSource];
