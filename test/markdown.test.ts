import { describe, expect, it } from "vitest";
import { toMarkdown } from "../src/markdown.js";
import { severityBreakdown } from "../src/report.js";
import type { Finding } from "../src/types.js";

const finding: Finding = {
  dependency: { ecosystem: "npm", name: "qs", version: "6.7.0", paths: [], direct: false, dev: false, introducedBy: ["express"] },
  vulns: [
    { id: "GHSA-a", aliases: ["CVE-2022-24999"], summary: "", details: "", severity: "HIGH", fixedVersions: [], fixCommits: [] },
    { id: "GHSA-b", aliases: [], summary: "", details: "", severity: "MODERATE", fixedVersions: [], fixCommits: [] },
  ],
  safeVersion: "6.16.0",
  unfixable: [],
  breaking: false,
  usages: [],
  via: [{ package: "express", usages: [{ file: "src/server.ts", line: 2, column: 13, specifier: "express", symbol: "default()", snippet: "", mentionedBy: [] }] }],
  reachability: "imported",
};

describe("toMarkdown", () => {
  it("summarizes each vulnerable package in one row", () => {
    const md = toMarkdown([{ lockfile: "package-lock.json", findings: [finding] }]);
    expect(md).toContain("2 vulnerabilities in 1 packages (1 high, 1 moderate).");
    expect(md).toContain("| `qs@6.7.0` (via express) | HIGH | CVE-2022-24999, GHSA-b | imported | `src/server.ts:2` | → 6.16.0 |");
  });

  it("gives each project its own section and reports clean ones", () => {
    const md = toMarkdown([
      { lockfile: "web/package-lock.json", findings: [finding] },
      { lockfile: "api/uv.lock", findings: [] },
    ]);
    expect(md).toContain("### `web/package-lock.json`");
    expect(md).toContain("### `api/uv.lock`\n\nNo known vulnerabilities.");
  });
});

describe("severityBreakdown", () => {
  it("counts vulnerabilities per severity, most severe first", () => {
    const withSev = (...sev: (string | undefined)[]): Finding => ({
      ...finding,
      vulns: sev.map((s, i) => ({ id: `V${i}`, aliases: [], summary: "", details: "", severity: s, fixedVersions: [], fixCommits: [] })),
    });
    expect(severityBreakdown([withSev("LOW", "HIGH", "MEDIUM"), withSev("CRITICAL", undefined, "HIGH")])).toBe(
      "1 critical, 2 high, 1 moderate, 1 low, 1 unrated",
    );
  });
});
