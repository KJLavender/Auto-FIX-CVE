import { describe, expect, it } from "vitest";
import { isBreakingUpgrade, mentionPattern } from "../src/scan.js";

describe("mentionPattern", () => {
  it("requires code formatting for plain English words", () => {
    expect(mentionPattern("get").test("an attacker can get credentials")).toBe(false);
    expect(mentionPattern("merge").test("uses assignInWith to merge imports")).toBe(false);
    expect(mentionPattern("get").test("calling axios.get(url) leaks")).toBe(true);
    expect(mentionPattern("template").test("validation in `_.template` was missing")).toBe(true);
    expect(mentionPattern("merge").test("the `merge` function")).toBe(true);
    expect(mentionPattern("template").test("Command Injection via the template function")).toBe(true);
  });

  it("matches distinctive identifiers anywhere", () => {
    expect(mentionPattern("zipObjectDeep").test("prototype pollution via zipObjectDeep")).toBe(true);
  });
});

describe("isBreakingUpgrade", () => {
  it("follows semver, including 0.x rules", () => {
    expect(isBreakingUpgrade("4.17.20", "4.18.0")).toBe(false);
    expect(isBreakingUpgrade("1.2.5", "1.2.6")).toBe(false);
    expect(isBreakingUpgrade("3.0.0", "4.0.0")).toBe(true);
    expect(isBreakingUpgrade("0.21.0", "0.34.0")).toBe(true);
    expect(isBreakingUpgrade("0.21.0", "0.21.4")).toBe(false);
    expect(isBreakingUpgrade("0.0.1", "0.0.2")).toBe(true);
  });
});
