import { describe, expect, it } from "vitest";
import { correlate, cvesOf, type Exposure } from "../src/correlate.js";
import { changelogCves } from "../src/runtime/sources.js";
import type { Vulnerability } from "../src/types.js";

const v = (id: string, extra: Partial<Vulnerability> = {}): Vulnerability => ({
  id,
  aliases: [],
  summary: "",
  details: "",
  fixedVersions: [],
  fixCommits: [],
  ...extra,
});

describe("cvesOf", () => {
  it("reads CVEs from ids, aliases and upstream ids, including Debian's prefixed ones", () => {
    expect(cvesOf(v("GHSA-x", { aliases: ["CVE-2021-1"] }))).toEqual(["CVE-2021-1"]);
    expect(cvesOf(v("DSA-5532-1", { upstream: ["CVE-2023-5363", "DEBIAN-CVE-2023-5363"] }))).toEqual(["CVE-2023-5363"]);
    expect(cvesOf(v("DEBIAN-CVE-2026-111497"))).toEqual(["CVE-2026-111497"]);
    expect(cvesOf(v("NODE-SECURITY-22.23.4"))).toEqual([]);
  });
});

describe("correlate", () => {
  const brotli = "CVE-2026-111497";
  const exposures: Exposure[] = [
    { where: "api/Dockerfile:1", component: "Node.js 22.20.0", fix: "node:22.23.4", vulns: [v(brotli, { aliases: [brotli], summary: "Brotli OOB write" })] },
    { where: "backend/Dockerfile:3", component: ".NET 8.0.30", fix: "aspnet:8.0.33", vulns: [v(brotli, { aliases: [brotli], summary: "Fixed in .NET 8.0.33" })] },
    {
      where: "api.cdx.json",
      component: "brotli 1.0.9-2 (libbrotli1)",
      fix: "brotli 1.0.9-2+deb12u1",
      vulns: [v(`DEBIAN-${brotli}`, { knownExploited: true }), v("DEBIAN-CVE-2026-2")],
      unfixable: ["DEBIAN-CVE-2026-2"],
    },
    { where: "web/package-lock.json", component: "lodash 4.17.20", fix: "lodash 4.17.21", vulns: [v("GHSA-a", { aliases: ["CVE-2026-2"] })] },
    // The same package in two projects is one component, not a cross-component finding.
    { where: "a/package-lock.json", component: "qs 6.7.0", vulns: [v("GHSA-q", { aliases: ["CVE-2026-3"] })] },
    { where: "b/package-lock.json", component: "qs 6.7.0", vulns: [v("GHSA-q", { aliases: ["CVE-2026-3"] })] },
  ];

  it("groups one CVE across runtimes and packages, each with its own fix", () => {
    const groups = correlate(exposures);
    expect(groups.map((g) => g.cve)).toEqual([brotli, "CVE-2026-2"]);
    expect(groups[0]).toMatchObject({ knownExploited: true, summary: "Brotli OOB write" });
    expect(groups[0].places.map((p) => [p.component, p.fix])).toEqual([
      ["Node.js 22.20.0", "node:22.23.4"],
      [".NET 8.0.30", "aspnet:8.0.33"],
      ["brotli 1.0.9-2 (libbrotli1)", "brotli 1.0.9-2+deb12u1"],
    ]);
    // An upgrade that leaves this one open is not offered as its fix.
    expect(groups[1].places.find((p) => p.component.startsWith("brotli"))?.fix).toBeUndefined();
  });
});

describe("changelogCves", () => {
  it("reads the CVEs a release section lists, without author names", () => {
    const md = [
      '<a id="22.23.4"></a>',
      "## 2026-10-21, Version 22.23.4 'Jod' (LTS)",
      "* (CVE-2026-111497) deps: brotli: cherry-pick 0ed4268 (Evgenii Kliuchnikov)",
      "* (CVE-2026-111497) src: expose error (Antoine du Hamel)",
      "* (CVE-2026-1, CVE-2026-2) http: two fixes (Someone)",
      "* deps: update c-ares (Bot)",
      '<a id="22.23.3"></a>',
      "* (CVE-2026-9) older (X)",
    ].join("\n");
    expect([...changelogCves(md, "22.23.4")]).toEqual([
      ["CVE-2026-111497", "deps: brotli: cherry-pick 0ed4268"],
      ["CVE-2026-1", "http: two fixes"],
      ["CVE-2026-2", "http: two fixes"],
    ]);
    expect(changelogCves(md, "99.0.0").size).toBe(0);
  });
});
