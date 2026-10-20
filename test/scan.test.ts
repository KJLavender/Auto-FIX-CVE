import { describe, expect, it } from "vitest";
import { mentionPattern } from "../src/scan.js";

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
