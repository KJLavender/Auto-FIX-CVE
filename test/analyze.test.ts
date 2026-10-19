import { describe, expect, it } from "vitest";
import { findUsagesInSource } from "../src/impact/analyze.js";

const symbols = (src: string, pkg: string, file = "a.ts") =>
  (findUsagesInSource(file, src, [pkg]).get(pkg) ?? []).map((u) => `${u.line}:${u.symbol}`);

describe("findUsagesInSource", () => {
  it("resolves default, named, aliased and namespace imports", () => {
    const src = [
      'import _ from "lodash";',
      'import { merge, get as pick } from "lodash";',
      'import * as L from "lodash";',
      "_.template(x);",
      "merge(a, b);",
      "pick(o, 'k');",
      "L.zipObjectDeep(a, b);",
    ].join("\n");
    expect(symbols(src, "lodash")).toEqual(["4:template", "5:merge", "6:get", "7:zipObjectDeep"]);
  });

  it("handles CommonJS require forms", () => {
    const src = [
      'const axios = require("axios");',
      'const { post } = require("axios");',
      'require("axios").put(u);',
      "axios.get(u);",
      "post(u);",
    ].join("\n");
    expect(symbols(src, "axios", "a.js")).toEqual(["3:put", "4:get", "5:post"]);
  });

  it("matches subpath imports but not packages sharing a prefix", () => {
    const src = ['import fp from "lodash/fp";', 'import x from "lodash-es";', "fp.map(f);", "x.map(f);"].join("\n");
    const usages = findUsagesInSource("a.ts", src, ["lodash"]).get("lodash") ?? [];
    expect(usages.map((u) => [u.specifier, u.symbol])).toEqual([["lodash/fp", "map"]]);
  });

  it("reports side-effect, re-export and dynamic imports", () => {
    const src = ['import "minimist";', 'export { default } from "minimist";', 'await import("minimist");'].join("\n");
    expect(symbols(src, "minimist")).toEqual(["1:(side-effect import)", "2:(re-export)", "3:(dynamic import)"]);
  });

  it("ignores property names that happen to match a binding", () => {
    const src = ['import { merge } from "lodash";', "obj.merge();", "const o = { merge: 1 };"].join("\n");
    expect(symbols(src, "lodash")).toEqual([]);
  });
});
