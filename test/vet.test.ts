import { describe, expect, it } from "vitest";
import type { OsvClient } from "../src/osv/client.js";
import { goEscape, normalizeLicense, type PackageMeta } from "../src/package-meta.js";
import type { Vulnerability } from "../src/types.js";
import { licenseVerdict, parseSpec, vetPackage, type VetPolicy } from "../src/vet.js";

describe("parseSpec", () => {
  it("reads ecosystems, scopes and pins", () => {
    expect(parseSpec("lodash")).toEqual({ ecosystem: "npm", name: "lodash" });
    expect(parseSpec("@angular/core@20.1.0")).toEqual({ ecosystem: "npm", name: "@angular/core", version: "20.1.0" });
    expect(parseSpec("pypi:Flask_Login==0.6.3")).toEqual({ ecosystem: "PyPI", name: "flask-login", version: "0.6.3" });
    expect(parseSpec("go:github.com/gin-gonic/gin@v1.9.0")).toEqual({ ecosystem: "Go", name: "github.com/gin-gonic/gin", version: "v1.9.0" });
    expect(parseSpec("cargo:serde")).toEqual({ ecosystem: "crates.io", name: "serde" });
    expect(parseSpec("nuget:Newtonsoft.Json@13.0.1")).toEqual({ ecosystem: "NuGet", name: "Newtonsoft.Json", version: "13.0.1" });
    expect(() => parseSpec("maven:x@1")).toThrow(/Unknown ecosystem/);
  });
});

describe("licenses", () => {
  it("normalises free text and applies allow and deny lists to SPDX expressions", () => {
    expect(normalizeLicense("Apache 2.0")).toBe("Apache-2.0");
    expect(normalizeLicense("MIT License")).toBe("MIT");
    expect(normalizeLicense("x".repeat(200))).toBeUndefined();
    expect(licenseVerdict("MIT OR GPL-3.0", undefined, ["GPL-3.0"])).toBe("allowed");
    expect(licenseVerdict("MIT AND GPL-3.0", undefined, ["GPL-3.0"])).toBe("denied");
    expect(licenseVerdict("(MIT OR Apache-2.0)", ["Apache-2.0"])).toBe("allowed");
    expect(licenseVerdict("BSD-3-Clause", ["MIT"])).toBe("denied");
    expect(licenseVerdict(undefined, ["MIT"])).toBe("unknown");
  });

  it("escapes capitals in Go module paths", () => {
    expect(goEscape("github.com/Azure/azure-sdk")).toBe("github.com/!azure/azure-sdk");
  });
});

const NOW = new Date("2026-10-27T00:00:00Z");
const policy: VetPolicy = { minAgeDays: 7 };
const vuln = (id: string, extra: Partial<Vulnerability> = {}): Vulnerability => ({
  id, aliases: [], summary: "", details: "", fixedVersions: ["2.0.0"], fixCommits: [], severity: "HIGH", ...extra,
});

function fakeOsv(vulns: Vulnerability[], safe?: string): OsvClient {
  return {
    queryBatch: async () => [vulns.map((v) => v.id)],
    getVulns: async () => vulns,
    findSafeVersion: async () => ({ version: safe, unfixable: [] }),
  } as unknown as OsvClient;
}
const meta = (m: Partial<PackageMeta>) => async (): Promise<PackageMeta> => ({ exists: true, version: "1.0.0", published: "2025-01-01T00:00:00Z", license: "MIT", ...m });

describe("vetPackage", () => {
  it("passes an old, clean, licensed release", async () => {
    const r = await vetPackage(parseSpec("ok@1.0.0"), policy, { meta: meta({}), osv: fakeOsv([]), now: NOW });
    expect(r.verdict).toBe("pass");
  });

  it("fails on vulnerabilities, with the fixing version; minor ones only warn", async () => {
    const r = await vetPackage(parseSpec("x@1.0.0"), policy, { meta: meta({}), osv: fakeOsv([vuln("GHSA-1")], "2.0.0"), now: NOW });
    expect(r).toMatchObject({ verdict: "fail", safeVersion: "2.0.0" });
    expect(r.checks[0].message).toMatch(/GHSA-1 \(high\); 2\.0\.0 fixes them/);
    const low = await vetPackage(parseSpec("x@1.0.0"), { ...policy, minSeverity: "high" }, { meta: meta({}), osv: fakeOsv([vuln("GHSA-2", { severity: "LOW" })]), now: NOW });
    expect(low.verdict).toBe("warn");
  });

  it("fails on malware, deprecation and yanks; warns on young releases and unknown licenses", async () => {
    const mal = await vetPackage(parseSpec("x@1.0.0"), policy, { meta: meta({}), osv: fakeOsv([vuln("MAL-2026-1", { malicious: true })]), now: NOW });
    expect(mal.checks.some((c) => c.level === "fail" && c.message.startsWith("MALICIOUS"))).toBe(true);
    expect((await vetPackage(parseSpec("x@1.0.0"), policy, { meta: meta({ deprecated: "use y" }), osv: fakeOsv([]), now: NOW })).verdict).toBe("fail");
    expect((await vetPackage(parseSpec("x@1.0.0"), policy, { meta: meta({ yanked: true }), osv: fakeOsv([]), now: NOW })).verdict).toBe("fail");
    const young = await vetPackage(parseSpec("x@1.0.0"), policy, { meta: meta({ published: "2026-10-25T00:00:00Z", license: undefined }), osv: fakeOsv([]), now: NOW });
    expect(young.verdict).toBe("warn");
    expect(young.checks.map((c) => c.message)).toEqual(expect.arrayContaining([expect.stringMatching(/published 2 day/), "license unknown"]));
    expect((await vetPackage(parseSpec("x@1.0.0"), { ...policy, strict: true }, { meta: meta({ published: "2026-10-25T00:00:00Z" }), osv: fakeOsv([]), now: NOW })).verdict).toBe("fail");
  });

  it("still names unpublished malware", async () => {
    const r = await vetPackage(parseSpec("event-stream@3.3.6"), policy, {
      meta: async () => ({ exists: false, version: "3.3.6" }),
      osv: fakeOsv([vuln("GHSA-mh6f-8j2x-4483", { malicious: true })]),
      now: NOW,
    });
    expect(r.verdict).toBe("fail");
    expect(r.checks.map((c) => c.message)).toEqual(["not found in the npm registry at 3.3.6", expect.stringMatching(/^MALICIOUS: GHSA-mh6f/)]);
  });
});
