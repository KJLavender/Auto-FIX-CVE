import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { readBaseline, splitByBaseline, writeBaseline } from "../src/baseline.js";
import type { Finding, Vulnerability } from "../src/types.js";

const vuln = (id: string): Vulnerability => ({ id, aliases: [], summary: "", details: "", fixedVersions: [], fixCommits: [] });
const finding = (name: string, version: string, ids: string[]): Finding => ({
  dependency: { ecosystem: "npm", name, version, paths: [], direct: true, dev: false, introducedBy: [name] },
  vulns: ids.map(vuln),
  unfixable: [],
  breaking: false,
  usages: [],
  via: [],
  reachability: "imported",
});

describe("baseline", () => {
  it("lets only vulnerabilities that appeared after the baseline through", async () => {
    const file = path.join(await mkdtemp(path.join(tmpdir(), "autofix-baseline-")), "baseline.json");
    expect(await writeBaseline(file, [finding("lodash", "4.17.20", ["GHSA-a", "GHSA-b"]), finding("axios", "0.21.0", ["GHSA-c"])])).toBe(3);

    const later = [
      finding("lodash", "4.17.20", ["GHSA-a", "GHSA-b", "GHSA-new"]), // a new advisory for a known package
      finding("axios", "0.21.0", ["GHSA-c"]), // nothing new
      finding("minimist", "1.2.5", ["GHSA-d"]), // a new package
    ];
    const { fresh, known } = splitByBaseline(later, await readBaseline(file));
    expect(known).toBe(3);
    expect(fresh.map((f) => `${f.dependency.name}:${f.vulns.map((v) => v.id).join(",")}`)).toEqual(["lodash:GHSA-new", "minimist:GHSA-d"]);
  });

  it("treats a missing baseline file as empty", async () => {
    expect((await readBaseline(path.join(tmpdir(), "does-not-exist.json"))).size).toBe(0);
  });
});
