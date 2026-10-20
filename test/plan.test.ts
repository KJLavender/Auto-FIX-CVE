import { describe, expect, it } from "vitest";
import { planFinding } from "../src/fix/upgrade.js";
import type { Finding } from "../src/types.js";

function finding(over: Partial<Finding> & { direct?: boolean; version?: string } = {}): Finding {
  const { direct = true, version = "1.0.0", ...rest } = over;
  return {
    dependency: { ecosystem: "npm", name: "pkg", version, paths: [], direct, dev: false, introducedBy: direct ? ["pkg"] : ["parent"] },
    vulns: [],
    safeVersion: "1.0.1",
    unfixable: [],
    breaking: false,
    usages: [],
    via: [],
    reachability: "imported",
    ...rest,
  };
}

const policy = { checks: ["npm test"], allowBreaking: true, backport: true, preferBackport: false };

describe("planFinding", () => {
  it("upgrades direct deps and overrides transitive ones", () => {
    expect(planFinding(finding(), policy).action).toBe("upgrade");
    expect(planFinding(finding({ direct: false }), policy).action).toBe("override");
  });

  it("never downgrades", () => {
    const step = planFinding(finding({ version: "2.0.0", safeVersion: "1.9.9" }), policy);
    expect(step).toMatchObject({ action: "skip", reason: expect.stringMatching(/not an upgrade/) });
  });

  it("skips what it cannot do safely", () => {
    expect(planFinding(finding({ safeVersion: undefined }), policy).reason).toMatch(/backport/);
    expect(planFinding(finding({ direct: false, breaking: true, safeVersion: "2.0.0" }), policy).reason).toMatch(/transitive/);
    expect(planFinding(finding({ breaking: true, safeVersion: "2.0.0" }), { ...policy, allowBreaking: false }).reason).toMatch(
      /--no-breaking/,
    );
    expect(planFinding(finding({ breaking: true, safeVersion: "2.0.0" }), { ...policy, checks: [] }).reason).toMatch(/--check/);
  });

  it("backports when an upgrade is impossible or unwanted, if a fix commit exists", () => {
    const vulns = [{ id: "GHSA-x", aliases: [], summary: "", details: "", fixedVersions: [], fixCommits: ["https://github.com/o/r/commit/abc1234"] }];
    const hoisted = (f: Finding) => ({ ...f, dependency: { ...f.dependency, paths: [`node_modules/${f.dependency.name}`] } });
    const breaking = hoisted(finding({ breaking: true, safeVersion: "2.0.0", vulns }));
    expect(planFinding(hoisted(finding({ safeVersion: undefined, vulns })), policy).action).toBe("backport");
    expect(planFinding(hoisted(finding({ direct: false, breaking: true, safeVersion: "2.0.0", vulns })), policy).action).toBe("backport");
    expect(planFinding(breaking, { ...policy, allowBreaking: false }).action).toBe("backport");
    expect(planFinding(breaking, { ...policy, preferBackport: true }).action).toBe("backport");
    expect(planFinding(breaking, policy).action).toBe("upgrade");
    expect(planFinding(breaking, { ...policy, allowBreaking: false, backport: false }).action).toBe("skip");
    // Not hoisted: the PoC could not load this copy by name.
    expect(planFinding(finding({ breaking: true, safeVersion: "2.0.0", vulns }), { ...policy, preferBackport: true }).action).toBe("upgrade");
  });

  it("allows non-breaking upgrades without checks", () => {
    expect(planFinding(finding(), { ...policy, checks: [] }).action).toBe("upgrade");
  });
});
