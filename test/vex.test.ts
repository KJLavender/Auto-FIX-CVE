import { describe, expect, it } from "vitest";
import type { Finding, Vulnerability } from "../src/types.js";
import { openVex, purlsOf, vexStatements, type VexStatement } from "../src/vex.js";

const vuln = (id: string, aliases: string[]): Vulnerability => ({ id, aliases, summary: "", details: "", fixedVersions: [], fixCommits: [] });

const finding = (name: string, version: string, vulns: Vulnerability[], verdict?: "reachable" | "not-reachable"): Finding => ({
  dependency: { ecosystem: "npm", name, version, paths: [], direct: true, dev: false, introducedBy: [name] },
  vulns,
  unfixable: [],
  breaking: false,
  usages: [],
  via: [],
  reachability: "imported",
  ...(verdict ? { triage: { verdict, reasoning: `${name}: only called with constants`, conditions: "" } } : {}),
});

describe("purlsOf", () => {
  it("builds package URLs per ecosystem", () => {
    expect(purlsOf({ ecosystem: "npm", name: "@angular/core", version: "20.0.0" })).toEqual(["pkg:npm/%40angular/core@20.0.0"]);
    expect(purlsOf({ ecosystem: "PyPI", name: "flask", version: "2.0.0" })).toEqual(["pkg:pypi/flask@2.0.0"]);
    expect(purlsOf({ ecosystem: "Go", name: "github.com/gin-gonic/gin", version: "v1.9.0" })).toEqual(["pkg:golang/github.com/gin-gonic/gin@v1.9.0"]);
    expect(purlsOf({ ecosystem: "NuGet", name: "Newtonsoft.Json", version: "12.0.1" })).toEqual(["pkg:nuget/Newtonsoft.Json@12.0.1"]);
    expect(
      purlsOf({ ecosystem: "Debian:12", name: "openssl", version: "3.0.11-1~deb12u1", binaries: [{ name: "libssl3", version: "3.0.11-1~deb12u1" }] }),
    ).toEqual(["pkg:deb/debian/libssl3@3.0.11-1~deb12u1"]);
  });
});

describe("vexStatements", () => {
  const sources = {
    findings: [
      finding("lodash", "4.17.20", [vuln("GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"])], "not-reachable"),
      finding("qs", "6.7.0", [vuln("GHSA-hrpp-h998-j3pp", ["CVE-2022-24999"])], "reachable"),
      finding("minimist", "1.2.0", [vuln("GHSA-xvch-5gv4-984h", ["CVE-2021-44906"])]),
    ],
    ignored: [
      {
        ecosystem: "npm" as const,
        package: "semver",
        version: "5.7.1",
        id: "GHSA-c2qf-rxjj-qqgw",
        aliases: ["CVE-2022-25883"],
        reason: "Ranges come from our own config, never from users",
        until: "2027-01-01",
        justification: "vulnerable_code_cannot_be_controlled_by_adversary" as const,
      },
      { ecosystem: "npm" as const, package: "ws", version: "7.0.0", id: "GHSA-x", aliases: [], reason: "accepted, no claim" },
    ],
    backports: [{ package: "marked", version: "2.1.3", vulns: ["GHSA-rrrm-qjm4-v8hf"] }],
  };

  it("states only what is backed: a not-reachable verdict, a justified ignore rule, a proven backport", () => {
    const st = vexStatements(sources);
    expect(st.map((s) => [s.vulnerability.name, s.status, s.justification, s.products[0]["@id"]])).toEqual([
      ["CVE-2021-23337", "not_affected", "vulnerable_code_not_in_execute_path", "pkg:npm/lodash@4.17.20"],
      ["CVE-2022-25883", "not_affected", "vulnerable_code_cannot_be_controlled_by_adversary", "pkg:npm/semver@5.7.1"],
      ["GHSA-rrrm-qjm4-v8hf", "fixed", undefined, "pkg:npm/marked@2.1.3"],
    ]);
    expect(st[0].vulnerability.aliases).toEqual(["GHSA-35jh-r3h4-6jhm"]);
    expect(st[0].impact_statement).toContain("only called with constants");
    expect(st[1].status_notes).toBe("Accepted until 2027-01-01.");
  });

  it("names packages as subcomponents of a given product, and gives stable document ids", () => {
    const st = vexStatements(sources, "pkg:oci/api@sha256%3Aabc");
    expect(st[0].products).toEqual([{ "@id": "pkg:oci/api@sha256%3Aabc", subcomponents: [{ "@id": "pkg:npm/lodash@4.17.20" }] }]);
    const a = openVex(st, new Date("2026-10-27T00:00:00Z")) as { "@id": string; statements: VexStatement[]; "@context": string };
    const b = openVex(st, new Date("2026-10-28T00:00:00Z")) as { "@id": string };
    expect(a["@context"]).toBe("https://openvex.dev/ns/v0.2.0");
    expect(a["@id"]).toBe(b["@id"]);
  });
});
