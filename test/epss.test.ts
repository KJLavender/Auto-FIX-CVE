import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { epssLabel, loadEpss, markEpss, maxEpss, resetEpss } from "../src/epss.js";
import { fails } from "../src/scan.js";
import type { Finding, Vulnerability } from "../src/types.js";

const v = (id: string, extra: Partial<Vulnerability> = {}): Vulnerability => ({
  id,
  aliases: [],
  summary: "",
  details: "",
  severity: "MODERATE",
  fixedVersions: [],
  fixCommits: [],
  ...extra,
});

afterEach(() => {
  process.env.AUTOFIX_EPSS_URL = "off";
  resetEpss();
});

async function useScores(data: { cve: string; epss: string; percentile: string }[]) {
  const dir = await mkdtemp(path.join(tmpdir(), "autofix-epss-"));
  const file = path.join(dir, "epss.json");
  await writeFile(file, JSON.stringify({ status: "OK", data }));
  process.env.AUTOFIX_EPSS_URL = file;
  resetEpss();
}

describe("EPSS", () => {
  it("scores each vulnerability by the highest of the CVEs it is about", async () => {
    await useScores([
      { cve: "CVE-2026-111497", epss: "0.360270000", percentile: "0.98463" },
      { cve: "CVE-2023-5363", epss: "0.004", percentile: "0.7" },
      { cve: "CVE-2023-0001", epss: "0.02", percentile: "0.9" },
    ]);
    const node = v("CVE-2026-111497", { aliases: ["CVE-2026-111497"] });
    const dsa = v("DSA-5532-1", { upstream: ["CVE-2023-5363", "CVE-2023-0001"] });
    const none = v("GHSA-zzzz", { aliases: ["CVE-1999-0001"] });
    await markEpss([node, dsa, none]);
    expect(node.epss).toEqual({ score: 0.36027, percentile: 0.98463 });
    expect(dsa.epss?.score).toBe(0.02);
    expect(none.epss).toBeUndefined();
    expect(maxEpss([node, dsa, none])).toBe(0.36027);
    expect([epssLabel(node), epssLabel(dsa), epssLabel(v("x", { epss: { score: 0.004, percentile: 0.5 } }))]).toEqual(["EPSS 36%", "EPSS 2.0%", ""]);
  });

  it("is skipped when off or unavailable", async () => {
    expect((await loadEpss(["CVE-2026-111497"])).size).toBe(0);
    process.env.AUTOFIX_EPSS_URL = path.join(tmpdir(), "no-such-epss.json");
    resetEpss();
    expect((await loadEpss(["CVE-2026-111497"])).size).toBe(0);
  });

  it("lets --fail-on risk also fail on likely exploitation", () => {
    const f = {
      dependency: { ecosystem: "npm", name: "x", version: "1.0.0", paths: [], direct: true, dev: false, introducedBy: ["x"] },
      vulns: [v("A", { epss: { score: 0.36, percentile: 0.98 } })],
      unfixable: [],
      breaking: false,
      usages: [],
      via: [],
      reachability: "not-imported",
    } as Finding;
    expect(fails(f, "risk")).toBe(false);
    expect(fails(f, "risk", 0.1)).toBe(true);
    expect(fails(f, "risk", 0.5)).toBe(false);
  });
});
