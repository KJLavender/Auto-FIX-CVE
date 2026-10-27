import { readFile } from "node:fs/promises";
import path from "node:path";
import { detectLockfile, lockfileLine, type LockRef } from "./lockfile/index.js";
import type { Finding, Vulnerability } from "./types.js";

// GitHub code scanning ranks alerts by this numeric score (CVSS-like, 0-10).
const SECURITY_SEVERITY: Record<string, string> = { CRITICAL: "9.5", HIGH: "8.0", MODERATE: "5.5", MEDIUM: "5.5", LOW: "3.0" };
const LEVEL: Record<string, "error" | "warning" | "note"> = { CRITICAL: "error", HIGH: "error", MODERATE: "warning", MEDIUM: "warning", LOW: "note" };

interface Location {
  physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number; startColumn?: number } };
  message?: { text: string };
}

function cveOf(v: Vulnerability): string | undefined {
  return v.aliases.find((a) => a.startsWith("CVE-"));
}

function location(uri: string, startLine: number, startColumn?: number, text?: string): Location {
  return {
    physicalLocation: { artifactLocation: { uri }, region: { startLine, ...(startColumn ? { startColumn } : {}) } },
    ...(text ? { message: { text } } : {}),
  };
}

interface SarifRule {
  id: string;
  [key: string]: unknown;
}

export interface SarifLog {
  $schema: string;
  version: string;
  runs: {
    tool: { driver: { name: string; version: string; informationUri: string; rules: SarifRule[] } };
    results: object[];
  }[];
}

/** Combines per-project logs into one run, so code scanning shows a monorepo as a single report. */
export function mergeSarif(logs: SarifLog[]): SarifLog {
  const [first, ...rest] = logs;
  const run = first.runs[0];
  const ids = new Set(run.tool.driver.rules.map((r) => r.id));
  for (const log of rest) {
    for (const rule of log.runs[0].tool.driver.rules) if (!ids.has(rule.id) && ids.add(rule.id)) run.tool.driver.rules.push(rule);
    run.results.push(...log.runs[0].results);
  }
  return first;
}

/**
 * Builds a SARIF 2.1.0 log: one alert per vulnerable package on its lockfile
 * entry, plus one per call site whose API the advisory names, so code
 * scanning annotates the exact line that reaches the vulnerable code.
 */
export async function toSarif(
  projectDir: string,
  findings: Finding[],
  version: string,
  baseDir = process.cwd(),
  lockRef: LockRef = detectLockfile(projectDir),
): Promise<SarifLog> {
  // Code scanning resolves URIs against the repository root, which is where CI runs.
  const uri = (file: string) => path.relative(baseDir, path.join(projectDir, file)).split(path.sep).join("/");
  const { file: lockName, kind } = lockRef;
  const lock = (await readFile(path.join(projectDir, lockName), "utf8")).split(/\r?\n/);
  const rules = new Map<string, SarifRule>();
  const results: object[] = [];

  for (const f of findings) {
    const { name, version: installed } = f.dependency;
    const fix = f.safeVersion ? `Upgrade to ${f.safeVersion}.` : "No fixed release; consider `autofix-cve fix` to backport the upstream patch.";
    for (const v of f.vulns) {
      const sev = v.severity?.toUpperCase() ?? "";
      const cve = cveOf(v);
      if (!rules.has(v.id)) {
        rules.set(v.id, {
          id: v.id,
          name: cve ?? v.id,
          shortDescription: { text: v.summary || v.id },
          fullDescription: { text: v.details.slice(0, 1000) || v.summary || v.id },
          helpUri: `https://osv.dev/vulnerability/${v.id}`,
          help: { text: `${v.summary}\n\nSee https://osv.dev/vulnerability/${v.id}` },
          defaultConfiguration: { level: LEVEL[sev] ?? "warning" },
          properties: {
            tags: ["security", "dependency", ...(cve ? [cve] : []), ...(v.knownExploited ? ["known-exploited"] : [])],
            "security-severity": SECURITY_SEVERITY[sev] ?? "5.0",
          },
        });
      }

      const named = f.usages.filter((u) => u.mentionedBy.includes(v.id));
      // A model verdict of "not reachable" keeps the alert but stops it from blocking.
      const level = v.knownExploited ? "error" : f.triage?.verdict === "not-reachable" ? "note" : (LEVEL[sev] ?? "warning");
      const triage = f.triage ? ` Triage: ${f.triage.verdict}. ${f.triage.reasoning}` : "";
      results.push({
        ruleId: v.id,
        level,
        message: {
          text: `${name}@${installed} is affected by ${cve ?? v.id}: ${v.summary}.${v.knownExploited ? " Known to be exploited in the wild (CISA KEV)." : ""} ${fix} Reachability: ${f.reachability}.${triage}`,
        },
        ...(f.triage ? { properties: { triage: f.triage } } : {}),
        locations: [location(uri(lockName), lockfileLine(kind, lock, name, installed))],
        relatedLocations: [
          ...f.usages.map((u) => location(uri(u.file), u.line, u.column, `uses ${name} (${u.symbol})`)),
          ...f.via.flatMap((v) =>
            v.usages.map((u) => location(uri(u.file), u.line, u.column, `uses ${v.package}, which pulls in ${name}`)),
          ),
        ]
          .slice(0, 20)
          .map((l, i) => ({ id: i, ...l })),
        partialFingerprints: { packageVuln: `${name}@${installed}/${v.id}` },
      });
      for (const u of named) {
        results.push({
          ruleId: v.id,
          level,
          message: { text: `Calls \`${u.symbol}\` from ${name}@${installed}, the API named in ${cve ?? v.id}. ${fix}` },
          locations: [location(uri(u.file), u.line, u.column)],
          partialFingerprints: { callSite: `${u.file}/${u.symbol}/${v.id}` },
        });
      }
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Auto-FIX-CVE",
            version,
            informationUri: "https://github.com/KJLavender/Auto-FIX-CVE",
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}
