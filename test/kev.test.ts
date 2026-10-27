import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadKev, markExploited, resetKev } from "../src/kev.js";
import { fails } from "../src/scan.js";
import type { Finding, Vulnerability } from "../src/types.js";

const vuln = (id: string, aliases: string[], severity = "MODERATE"): Vulnerability => ({
  id,
  aliases,
  summary: "",
  details: "",
  severity,
  fixedVersions: [],
  fixCommits: [],
});

const finding = (vulns: Vulnerability[], reachability: Finding["reachability"]): Finding => ({
  dependency: { ecosystem: "npm", name: "x", version: "1.0.0", paths: [], direct: true, dev: false, introducedBy: ["x"] },
  vulns,
  unfixable: [],
  breaking: false,
  usages: [],
  via: [],
  reachability,
});

afterEach(() => {
  process.env.AUTOFIX_KEV_URL = "off";
  resetKev();
});

describe("KEV catalog", () => {
  it("loads a local copy and marks vulnerabilities by any alias", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-kev-"));
    const file = path.join(dir, "kev.json");
    await writeFile(file, JSON.stringify({ vulnerabilities: [{ cveID: "CVE-2026-0001" }] }));
    process.env.AUTOFIX_KEV_URL = file;
    resetKev();
    const kev = await loadKev();
    const hit = vuln("GHSA-aaaa", ["cve-2026-0001"]);
    const miss = vuln("GHSA-bbbb", ["CVE-2026-0002"]);
    markExploited([hit, miss], kev);
    expect(hit.knownExploited).toBe(true);
    expect(miss.knownExploited).toBeUndefined();
  });

  it("is skipped when turned off or unreadable", async () => {
    expect(await loadKev()).toBeUndefined();
    process.env.AUTOFIX_KEV_URL = path.join(tmpdir(), "does-not-exist-kev.json");
    resetKev();
    expect(await loadKev()).toBeUndefined();
  });
});

describe("--fail-on risk", () => {
  it("fails on known-exploited, or high severity that is reached", () => {
    const exploited = { ...vuln("A", [], "LOW"), knownExploited: true };
    expect(fails(finding([exploited], "not-imported"), "risk")).toBe(true);
    expect(fails(finding([vuln("B", [], "HIGH")], "likely"), "risk")).toBe(true);
    expect(fails(finding([vuln("C", [], "HIGH")], "imported"), "risk")).toBe(false);
    expect(fails(finding([vuln("D", [], "MODERATE")], "likely"), "risk")).toBe(false);
    const triaged = { ...finding([vuln("E", [], "CRITICAL")], "likely"), triage: { verdict: "not-reachable" as const, reasoning: "", conditions: "" } };
    expect(fails(triaged, "risk")).toBe(false);
  });
});
