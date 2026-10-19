import { describe, expect, it } from "vitest";
import type { FixResult } from "../src/fix/upgrade.js";
import { prBody, prTitle } from "../src/pr.js";

const base: FixResult = {
  package: "lodash",
  from: "4.17.20",
  to: "4.18.0",
  strategy: "upgrade",
  status: "fixed",
  attempts: 0,
  changedFiles: ["package.json", "package-lock.json"],
  explanations: [],
  fixedVulns: ["GHSA-35jh-r3h4-6jhm (CVE-2021-23337)", "GHSA-29mw-wpgm-hmr9 (CVE-2020-28500)"],
  evidence: ["OSV reports no known vulnerabilities for lodash@4.18.0", "checks pass after the upgrade: npm test"],
  costUsd: 0,
};

const backport: FixResult = {
  ...base,
  package: "marked",
  from: "2.1.3",
  to: "2.1.3",
  strategy: "backport",
  fixedVulns: ["GHSA-rrrm-qjm4-v8hf (CVE-2022-21680)"],
  evidence: ["GHSA-rrrm-qjm4-v8hf: PoC reproduced the bug on unpatched 2.1.3, passes after patching"],
  explanations: ["Ported the ReDoS fix to all four copies."],
};

const skipped: FixResult = { ...base, package: "axios", from: "0.21.0", status: "skipped", reason: "no backport possible", fixedVulns: [] };

describe("PR content", () => {
  it("titles the PR with the number of fixed vulnerabilities and packages", () => {
    expect(prTitle([base, backport, skipped])).toBe("Fix 3 known vulnerabilities in lodash, marked");
    expect(prTitle([backport])).toBe("Fix 1 known vulnerability in marked");
  });

  it("lists every fix with its evidence, and what was not fixed", () => {
    const body = prBody([base, backport, skipped], []);
    expect(body).toContain("| `lodash` | 4.17.20 → 4.18.0 | upgrade | GHSA-35jh-r3h4-6jhm (CVE-2021-23337)<br>");
    expect(body).toContain("| `marked` | 2.1.3 (backported fix) | backport |");
    expect(body).toContain("- checks pass after the upgrade: npm test");
    expect(body).toContain("PoC reproduced the bug");
    expect(body).toContain("- `axios@0.21.0` (skipped): no backport possible");
    expect(body).toContain("No known vulnerabilities remain.");
    expect(body).not.toMatch(/claude/i);
  });
});
