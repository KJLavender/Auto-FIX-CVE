import { describe, expect, it } from "vitest";
import { canBackport } from "../src/backport/backport.js";
import { planFinding } from "../src/fix/upgrade.js";
import { mitigationCandidates } from "../src/mitigate.js";
import { isMaliciousRecord } from "../src/osv/client.js";
import { fails, isMalicious } from "../src/scan.js";
import type { Finding } from "../src/types.js";
import { vexStatements } from "../src/vex.js";

describe("malicious packages", () => {
  it("are recognised from OpenSSF ids, CWE-506 and GitHub malware advisories", () => {
    expect(isMaliciousRecord({ id: "MAL-2025-1", aliases: [] })).toBe(true);
    expect(isMaliciousRecord({ id: "GHSA-r8qm-c82c-c9r7", aliases: ["MAL-2025-1"] })).toBe(true);
    expect(isMaliciousRecord({ id: "GHSA-mh6f-8j2x-4483", aliases: [], database_specific: { cwe_ids: ["CWE-506"] } })).toBe(true);
    expect(isMaliciousRecord({ id: "GHSA-c2m4-w5hm-vqjw", aliases: [], summary: "crossenv is malware" })).toBe(true);
    expect(isMaliciousRecord({ id: "GHSA-x", aliases: ["CVE-2021-1"], summary: "Prototype pollution in malware-scanner" })).toBe(false);
  });

  const finding = (safeVersion?: string): Finding => ({
    dependency: { ecosystem: "npm", name: "flatmap-stream", version: "0.1.1", paths: ["node_modules/flatmap-stream"], direct: false, dev: false, introducedBy: ["event-stream"] },
    vulns: [{ id: "MAL-2025-20690", aliases: [], summary: "Malicious code", details: "", severity: "CRITICAL", fixedVersions: [], fixCommits: ["https://github.com/x/y/commit/abcdef1"], malicious: true }],
    safeVersion,
    unfixable: safeVersion ? [] : ["MAL-2025-20690"],
    breaking: false,
    usages: [{ file: "a.js", line: 1, column: 1, specifier: "flatmap-stream", symbol: "default", snippet: "", mentionedBy: [] }],
    via: [],
    reachability: "not-imported",
    triage: { verdict: "not-reachable", reasoning: "never imported", conditions: "" },
  });

  it("fail every gate but none, and cannot be backported, mitigated or stated away in VEX", () => {
    const f = finding();
    expect(isMalicious(f)).toBe(true);
    for (const level of ["any", "likely", "high", "risk"] as const) expect(fails(f, level)).toBe(true);
    expect(fails(f, "none")).toBe(false);
    expect(canBackport(f)).toBe(false);
    expect(mitigationCandidates([f])).toEqual([]);
    expect(vexStatements({ findings: [f], ignored: [], backports: [] })).toEqual([]);
  });

  it("are removed, or moved off the hijacked release when a clean one exists", () => {
    const policy = { checks: ["npm test"], allowBreaking: true, backport: true, preferBackport: false, canOverride: true };
    expect(planFinding(finding(), policy)).toMatchObject({ action: "skip", reason: expect.stringMatching(/MALICIOUS.*remove it/) });
    expect(planFinding(finding("0.1.2"), policy).action).toBe("override");
  });
});
