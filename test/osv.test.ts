import { afterEach, describe, expect, it, vi } from "vitest";
import { OsvClient } from "../src/osv/client.js";
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

describe("findSafeVersion", () => {
  it("picks the smallest version that fixes everything", async () => {
    fakeOsv({ "1.0.0": ["A", "B"], "1.2.0": [] });
    const osv = new OsvClient();
    expect(await osv.findSafeVersion("pkg", "1.0.0", [vuln("A", ["1.1.0"]), vuln("B", ["1.2.0"])])).toEqual({
      version: "1.2.0",
      unfixable: [],
    });
  });

  it("does not stop at a version that is vulnerable to something else", async () => {
    fakeOsv({ "1.1.0": ["C"], "1.3.0": [] }, { C: ["1.3.0"] });
    const osv = new OsvClient();
    expect((await osv.findSafeVersion("pkg", "1.0.0", [vuln("A", ["1.1.0"])])).version).toBe("1.3.0");
  });

  it("fixes what it can when some vulnerabilities have no fixed release", async () => {
    fakeOsv({ "1.4.0": ["NOFIX"] });
    const osv = new OsvClient();
    expect(await osv.findSafeVersion("pkg", "0.10.0", [vuln("A", ["1.4.0"]), vuln("NOFIX", [])])).toEqual({
      version: "1.4.0",
      unfixable: ["NOFIX"],
    });
  });

  it("reports no upgrade when nothing is fixable", async () => {
    fakeOsv({});
    const osv = new OsvClient();
    expect(await osv.findSafeVersion("pkg", "1.0.0", [vuln("NOFIX", [])])).toEqual({ unfixable: ["NOFIX"] });
  });

  it("chooses the fix on the current release line over an older branch", async () => {
    fakeOsv({ "4.17.21": [] });
    const osv = new OsvClient();
    expect((await osv.findSafeVersion("pkg", "4.17.20", [vuln("A", ["3.10.2", "4.17.21", "5.0.1"])])).version).toBe("4.17.21");
  });
});
