import { afterEach, describe, expect, it, vi } from "vitest";
import { dedupeVulns, OsvClient } from "../src/osv/client.js";
import { cratesIndexPath } from "../src/registry.js";
import type { Vulnerability } from "../src/types.js";

const vuln = (id: string, fixedVersions: string[]): Vulnerability => ({
  id,
  aliases: [],
  summary: "",
  details: "",
  fixedVersions,
  fixCommits: [],
});

/** Fakes OSV: `affected` maps a version to the vulnerability ids OSV reports for it. */
function fakeOsv(affected: Record<string, string[]>, details: Record<string, string[]> = {}) {
  vi.stubGlobal("fetch", async (url: string, init?: { body?: string }) => {
    if (url.endsWith("/querybatch")) {
      const { queries } = JSON.parse(init!.body!) as { queries: { version: string }[] };
      return Response.json({ results: queries.map((q) => ({ vulns: (affected[q.version] ?? []).map((id) => ({ id })) })) });
    }
    const id = decodeURIComponent(url.split("/").pop()!);
    return Response.json({
      id,
      affected: [{ package: { name: "pkg", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: (details[id] ?? []).map((fixed) => ({ fixed })) }] }],
    });
  });
}

afterEach(() => vi.unstubAllGlobals());

const noRegistry = async () => undefined;

describe("findSafeVersion", () => {
  it("picks the smallest version that fixes everything", async () => {
    fakeOsv({ "1.0.0": ["A", "B"], "1.2.0": [] });
    const osv = new OsvClient(noRegistry);
    expect(await osv.findSafeVersion("pkg", "1.0.0", [vuln("A", ["1.1.0"]), vuln("B", ["1.2.0"])])).toEqual({
      version: "1.2.0",
      unfixable: [],
    });
  });

  it("does not stop at a version that is vulnerable to something else", async () => {
    fakeOsv({ "1.1.0": ["C"], "1.3.0": [] }, { C: ["1.3.0"] });
    const osv = new OsvClient(noRegistry);
    expect((await osv.findSafeVersion("pkg", "1.0.0", [vuln("A", ["1.1.0"])])).version).toBe("1.3.0");
  });

  it("fixes what it can when some vulnerabilities have no fixed release", async () => {
    fakeOsv({ "1.4.0": ["NOFIX"] });
    const osv = new OsvClient(noRegistry);
    expect(await osv.findSafeVersion("pkg", "0.10.0", [vuln("A", ["1.4.0"]), vuln("NOFIX", [])])).toEqual({
      version: "1.4.0",
      unfixable: ["NOFIX"],
    });
  });

  it("reports no upgrade when nothing is fixable", async () => {
    fakeOsv({});
    const osv = new OsvClient(noRegistry);
    expect(await osv.findSafeVersion("pkg", "1.0.0", [vuln("NOFIX", [])])).toEqual({ unfixable: ["NOFIX"] });
  });

  it("chooses the fix on the current release line over an older branch", async () => {
    fakeOsv({ "4.17.21": [] });
    const osv = new OsvClient(noRegistry);
    expect((await osv.findSafeVersion("pkg", "4.17.20", [vuln("A", ["3.10.2", "4.17.21", "5.0.1"])])).version).toBe("4.17.21");
  });
});

describe("dedupeVulns", () => {
  it("merges records of one vulnerability published under several ids", () => {
    const ghsa = { ...vuln("GHSA-ffqj", ["2.4.0"]), aliases: ["CVE-2022-29217", "PYSEC-2022-202"], severity: "HIGH" };
    const pysec = { ...vuln("PYSEC-2022-202", ["2.4.0"]), aliases: ["CVE-2022-29217", "GHSA-ffqj"], fixCommits: ["https://github.com/x/y/commit/abc1234"] };
    const other = { ...vuln("PYSEC-2025-183", []), aliases: ["CVE-2025-45768"] };
    const merged = dedupeVulns([pysec, other, ghsa]);
    expect(merged.map((v) => v.id)).toEqual(["GHSA-ffqj", "PYSEC-2025-183"]);
    expect(merged[0]).toMatchObject({ severity: "HIGH", fixCommits: ["https://github.com/x/y/commit/abc1234"] });
    expect(merged[0].aliases.sort()).toEqual(["CVE-2022-29217", "PYSEC-2022-202"]);
  });

  it("joins groups that only connect through a later record", () => {
    const a = { ...vuln("A", []), aliases: ["CVE-1"] };
    const b = { ...vuln("B", []), aliases: ["CVE-2"] };
    const bridge = { ...vuln("GHSA-c", []), aliases: ["CVE-1", "CVE-2"] };
    expect(dedupeVulns([a, b, bridge]).map((v) => v.id)).toEqual(["GHSA-c"]);
  });
});

describe("findSafeVersion with accepted risks", () => {
  it("does not upgrade further just to fix an ignored vulnerability", async () => {
    fakeOsv({ "1.1.0": ["IGNORED"], "2.0.0": [] }, { IGNORED: ["2.0.0"] });
    const osv = new OsvClient(noRegistry);
    const safe = await osv.findSafeVersion("pkg", "1.0.0", [vuln("A", ["1.1.0"])], "npm", new Set(["IGNORED"]));
    expect(safe.version).toBe("1.1.0");
  });
});

describe("findSafeVersion with registry data", () => {
  it("skips a fixed release that was yanked or deprecated", async () => {
    fakeOsv({ "1.1.1": [] });
    const usable = async () => new Set(["1.0.0", "1.1.1", "1.2.0-beta.1", "1.2.0"]);
    const osv = new OsvClient(usable);
    expect((await osv.findSafeVersion("pkg", "1.0.0", [vuln("A", ["1.1.0"])])).version).toBe("1.1.1");
  });
});

describe("cratesIndexPath", () => {
  it("follows the sparse index layout", () => {
    expect(cratesIndexPath("a")).toBe("1/a");
    expect(cratesIndexPath("cc")).toBe("2/cc");
    expect(cratesIndexPath("syn")).toBe("3/s/syn");
    expect(cratesIndexPath("Serde")).toBe("se/rd/serde");
  });
});
