import pc from "picocolors";
import { markEpss } from "./epss.js";
import { loadKev, markExploited } from "./kev.js";
import { dedupeVulns, OsvClient } from "./osv/client.js";
import { fetchPackageMeta, type MetaFetcher, type PackageMeta } from "./package-meta.js";
import { meetsSeverity, type Severity } from "./scan.js";
import type { Vulnerability } from "./types.js";
import { normalizeName, type Ecosystem } from "./versions.js";

const PREFIX: Record<string, Ecosystem> = { npm: "npm", pypi: "PyPI", pip: "PyPI", go: "Go", golang: "Go", cargo: "crates.io", crates: "crates.io", nuget: "NuGet" };

export interface PackageSpec {
  ecosystem: Ecosystem;
  name: string;
  version?: string;
}

/**
 * `lodash`, `lodash@4.17.21`, `@scope/pkg@1.0.0`, `pypi:requests==2.31.0`,
 * `go:github.com/gin-gonic/gin@v1.9.0`, `cargo:serde@1.0.200`, `nuget:Newtonsoft.Json@13.0.1`.
 * Without a prefix the package is taken to be npm.
 */
export function parseSpec(spec: string): PackageSpec {
  const m = /^([a-z]+):(.+)$/i.exec(spec);
  const ecosystem = m ? PREFIX[m[1].toLowerCase()] : "npm";
  if (!ecosystem) throw new Error(`Unknown ecosystem in "${spec}"; use npm:, pypi:, go:, cargo: or nuget:.`);
  const rest = m ? m[2] : spec;
  const pin = rest.indexOf("==");
  if (pin > 0) return { ecosystem, name: normalizeName(ecosystem, rest.slice(0, pin)), version: rest.slice(pin + 2) };
  // A leading `@` is an npm scope, not a version separator.
  const at = rest.lastIndexOf("@");
  if (at > 0) return { ecosystem, name: normalizeName(ecosystem, rest.slice(0, at)), version: rest.slice(at + 1) };
  return { ecosystem, name: normalizeName(ecosystem, rest) };
}

/**
 * Whether an SPDX expression satisfies the policy. `A OR B` needs one allowed
 * choice; `A AND B` needs all. A denied id fails unless an OR offers another way.
 */
export function licenseVerdict(expression: string | undefined, allow?: string[], deny?: string[]): "allowed" | "denied" | "unknown" {
  if (!expression) return "unknown";
  const norm = (s: string) => s.trim().replace(/^\(|\)$/g, "").toLowerCase();
  const alternatives = expression.split(/\s+OR\s+/i).map((alt) => alt.split(/\s+AND\s+/i).map(norm));
  const allowed = new Set(allow?.map((l) => l.toLowerCase()));
  const denied = new Set(deny?.map((l) => l.toLowerCase()));
  const ok = (ids: string[]) => ids.every((id) => !denied.has(id) && (!allow || allowed.has(id)));
  return alternatives.some(ok) ? "allowed" : "denied";
}

export interface VetPolicy {
  /** Releases younger than this many days are flagged: hijacked versions are usually caught within days. */
  minAgeDays: number;
  allowLicenses?: string[];
  denyLicenses?: string[];
  /** Vulnerabilities rated below this only warn. */
  minSeverity?: Severity;
  /** Treat warnings as failures. */
  strict?: boolean;
}

export type Level = "pass" | "warn" | "fail";

export interface VetResult {
  spec: PackageSpec;
  version: string;
  verdict: Level;
  checks: { level: Level; message: string }[];
  vulns: Vulnerability[];
  safeVersion?: string;
  meta: PackageMeta;
}

export interface VetDeps {
  meta?: MetaFetcher;
  osv?: OsvClient;
  now?: Date;
}

const DAY = 86_400_000;

export async function vetPackage(spec: PackageSpec, policy: VetPolicy, deps: VetDeps = {}): Promise<VetResult> {
  const meta = await (deps.meta ?? fetchPackageMeta)(spec.ecosystem, spec.name, spec.version);
  const checks: VetResult["checks"] = [];
  const result: VetResult = { spec, version: meta.version, verdict: "pass", checks, vulns: [], meta };
  const osv = deps.osv ?? new OsvClient();
  if (!meta.exists) {
    checks.push({ level: "fail", message: `not found in the ${spec.ecosystem} registry${spec.version ? ` at ${spec.version}` : ""}` });
    // Malware is usually unpublished; say so, for anyone about to install it from an old lockfile or a mirror.
    if (spec.version) {
      const [ids] = await osv.queryBatch([{ name: spec.name, version: spec.version, ecosystem: spec.ecosystem }]);
      const malware = ids.length ? (await osv.getVulns(ids, spec.name, spec.ecosystem)).filter((v) => v.malicious) : [];
      if (malware.length) {
        result.vulns = malware;
        checks.push({ level: "fail", message: `MALICIOUS: ${malware.map((v) => v.id).join(", ")}; removed from the registry, but mirrors and lockfiles may still have it` });
      }
    }
    result.verdict = "fail";
    return result;
  }

  const [ids] = await osv.queryBatch([{ name: spec.name, version: meta.version, ecosystem: spec.ecosystem }]);
  const vulns = ids.length ? dedupeVulns(await osv.getVulns(ids, spec.name, spec.ecosystem)) : [];
  markExploited(vulns, await loadKev());
  await markEpss(vulns);
  result.vulns = vulns;
  const malware = vulns.filter((v) => v.malicious);
  if (malware.length) {
    checks.push({ level: "fail", message: `MALICIOUS: ${malware.map((v) => v.id).join(", ")}; do not install it` });
  }
  const bugs = vulns.filter((v) => !v.malicious);
  if (bugs.length) {
    const safe = await osv.findSafeVersion(spec.name, meta.version, bugs, spec.ecosystem);
    result.safeVersion = safe.version;
    const serious = bugs.filter((v) => v.knownExploited || meetsSeverity(v, policy.minSeverity));
    const list = bugs.map((v) => `${v.id}${v.severity ? ` (${v.severity.toLowerCase()})` : ""}${v.knownExploited ? " KNOWN EXPLOITED" : ""}`).join(", ");
    checks.push({
      level: serious.length ? "fail" : "warn",
      message: `${bugs.length} known vulnerabilit${bugs.length === 1 ? "y" : "ies"}: ${list}${safe.version ? `; ${safe.version} fixes them` : "; no fixed release"}`,
    });
  } else if (!malware.length) {
    checks.push({ level: "pass", message: "no known vulnerabilities" });
  }

  if (meta.deprecated) checks.push({ level: "fail", message: `deprecated: ${meta.deprecated}` });
  if (meta.yanked) checks.push({ level: "fail", message: "yanked or unlisted by its publisher" });

  const published = meta.published ? Date.parse(meta.published) : NaN;
  if (Number.isNaN(published)) {
    checks.push({ level: "warn", message: "release date unknown" });
  } else {
    const days = Math.floor(((deps.now ?? new Date()).getTime() - published) / DAY);
    checks.push(
      days < policy.minAgeDays
        ? { level: "warn", message: `published ${days} day(s) ago; hijacked releases are usually caught within days, so wait until it is ${policy.minAgeDays} days old` }
        : { level: "pass", message: `published ${days} days ago` },
    );
  }

  const license = licenseVerdict(meta.license, policy.allowLicenses, policy.denyLicenses);
  if (license === "unknown") checks.push({ level: policy.allowLicenses ? "fail" : "warn", message: "license unknown" });
  else checks.push({ level: license === "allowed" ? "pass" : "fail", message: `license ${meta.license}${license === "denied" ? " is not allowed by the policy" : ""}` });

  if (meta.latest && meta.latest !== meta.version) checks.push({ level: "pass", message: `latest release is ${meta.latest}` });

  const levels = checks.map((c) => (policy.strict && c.level === "warn" ? "fail" : c.level));
  result.verdict = levels.includes("fail") ? "fail" : levels.includes("warn") ? "warn" : "pass";
  return result;
}

const LABEL: Record<Level, string> = { pass: pc.green("PASS"), warn: pc.yellow("WARN"), fail: pc.red("FAIL") };
const MARK: Record<Level, string> = { pass: pc.green("✓"), warn: pc.yellow("!"), fail: pc.red("✗") };

export function formatVet(results: VetResult[]): string {
  const out: string[] = [];
  for (const r of results) {
    out.push(`${LABEL[r.verdict]}  ${pc.bold(`${r.spec.name}@${r.version || "?"}`)}  ${pc.dim(r.spec.ecosystem)}`);
    for (const c of r.checks) out.push(`  ${MARK[c.level]} ${c.message}`);
    out.push("");
  }
  return out.join("\n");
}
