import { describe, expect, it } from "vitest";
import { comparePep440, isBreakingUpgrade, normalizeName } from "../src/versions.js";

describe("isBreakingUpgrade", () => {
  it("follows semver for npm, including 0.x rules", () => {
    expect(isBreakingUpgrade("npm", "4.17.20", "4.18.0")).toBe(false);
    expect(isBreakingUpgrade("npm", "1.2.5", "1.2.6")).toBe(false);
    expect(isBreakingUpgrade("npm", "3.0.0", "4.0.0")).toBe(true);
    expect(isBreakingUpgrade("npm", "0.21.0", "0.34.0")).toBe(true);
    expect(isBreakingUpgrade("npm", "0.21.0", "0.21.4")).toBe(false);
    expect(isBreakingUpgrade("npm", "0.0.1", "0.0.2")).toBe(true);
  });

  it("treats a new major as breaking for PyPI", () => {
    expect(isBreakingUpgrade("PyPI", "5.3.1", "5.4")).toBe(false);
    expect(isBreakingUpgrade("PyPI", "2.11.2", "3.1.6")).toBe(true);
    expect(isBreakingUpgrade("PyPI", "0.9", "0.10.1")).toBe(true);
    expect(isBreakingUpgrade("PyPI", "1!1.0", "1!1.1")).toBe(false);
  });
});

describe("comparePep440", () => {
  it("orders dev < pre < final < post and ignores trailing zeros", () => {
    const sorted = ["1.0.post1", "1.0", "1.0rc1", "1.0a2", "1.0.dev0", "1.0b1", "0.9.9", "1.0a1"].sort(comparePep440);
    expect(sorted).toEqual(["0.9.9", "1.0.dev0", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1"]);
    expect(comparePep440("1.0", "1.0.0")).toBe(0);
    expect(comparePep440("2.0", "10.0")).toBe(-1);
    expect(comparePep440("1!0.1", "2.0")).toBe(1);
  });
});

describe("normalizeName", () => {
  it("applies PEP 503 to PyPI names only", () => {
    expect(normalizeName("PyPI", "PyYAML")).toBe("pyyaml");
    expect(normalizeName("PyPI", "zope.interface")).toBe("zope-interface");
    expect(normalizeName("npm", "Foo_Bar")).toBe("Foo_Bar");
  });
});
