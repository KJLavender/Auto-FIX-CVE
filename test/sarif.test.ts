import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { toSarif } from "../src/sarif.js";
import type { Finding } from "../src/types.js";

const finding: Finding = {
  dependency: { name: "lodash", version: "4.17.20", paths: ["node_modules/lodash"], direct: true, dev: false, introducedBy: ["lodash"] },
  vulns: [
    {
      id: "GHSA-35jh-r3h4-6jhm",
      aliases: ["CVE-2021-23337"],
      summary: "Command Injection in lodash",
      details: "via the template function",
      severity: "HIGH",
      fixedVersions: ["4.17.21"],
      fixCommits: [],
    },
  ],
  safeVersion: "4.17.21",
  breaking: false,
  usages: [
    { file: "src/render.ts", line: 5, column: 20, specifier: "lodash", symbol: "template", snippet: "", mentionedBy: ["GHSA-35jh-r3h4-6jhm"] },
    { file: "src/other.ts", line: 2, column: 1, specifier: "lodash", symbol: "merge", snippet: "", mentionedBy: [] },
  ],
  reachability: "likely",
};

describe("toSarif", () => {
  it("reports the lockfile entry and the call site named in the advisory, relative to the repo root", async () => {
    const repo = await mkdtemp(path.join(tmpdir(), "autofix-sarif-"));
    const project = path.join(repo, "app");
    await mkdir(project);
    await writeFile(
      path.join(project, "package-lock.json"),
      ["{", '  "packages": {', '    "": {},', '    "node_modules/lodash": {', '      "version": "4.17.20"', "    }", "  }", "}"].join("\n"),
    );

    const log = (await toSarif(project, [finding], "0.1.0", repo)) as any;
    const run = log.runs[0];
    expect(run.tool.driver.rules[0]).toMatchObject({
      id: "GHSA-35jh-r3h4-6jhm",
      name: "CVE-2021-23337",
      properties: { "security-severity": "8.0" },
    });
    const locs = run.results.map((r: any) => [r.locations[0].physicalLocation.artifactLocation.uri, r.locations[0].physicalLocation.region.startLine]);
    expect(locs).toEqual([
      ["app/package-lock.json", 4],
      ["app/src/render.ts", 5],
    ]);
    expect(run.results[0].relatedLocations).toHaveLength(2);
    expect(run.results[1].message.text).toContain("Calls `template`");
  });
});
