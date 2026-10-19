import path from "node:path";
import { describe, expect, it } from "vitest";
import { lockfileLine, readLockfile } from "../src/lockfile/index.js";
import { parseYarnV1 } from "../src/lockfile/yarn.js";

const FIXTURES = path.join(import.meta.dirname, "fixtures/lockfiles");

// The same package.json resolved by each package manager:
// axios 0.21.0 and lodash ^4.17.20 in dependencies, minimist 1.2.5 in devDependencies.
describe.each([
  ["npm", "npm", "package-lock.json"],
  ["pnpm9", "pnpm", "pnpm-lock.yaml"],
  ["pnpm8", "pnpm", "pnpm-lock.yaml"],
  ["yarn1", "yarn", "yarn.lock"],
  ["berry", "yarn", "yarn.lock"],
] as const)("%s lockfile", (dir, kind, file) => {
  it("yields the same dependency picture", async () => {
    const lock = await readLockfile(path.join(FIXTURES, dir));
    expect(lock).toMatchObject({ kind, file });
    const summary = lock.deps
      .map((d) => `${d.name} ${d.direct ? "direct" : "transitive"} ${d.dev ? "dev" : "prod"} via ${[...d.introducedBy].sort().join("+")}`)
      .sort();
    expect(summary).toEqual([
      "axios direct prod via axios",
      "follow-redirects transitive prod via axios",
      "lodash direct prod via lodash",
      "minimist direct dev via minimist",
    ]);
    expect(lock.deps.find((d) => d.name === "axios")?.version).toBe("0.21.0");
  });
});

describe("lockfile helpers", () => {
  it("resolves yarn v1 aliases to the real package name", () => {
    const entries = parseYarnV1(
      ['"string-width-cjs@npm:string-width@^4.2.0":', '  version "4.2.3"', "", '"@babel/core@^7.0.0", "@babel/core@^7.1.0":', '  version "7.24.0"'].join(
        "\n",
      ),
    );
    expect(entries.get("string-width-cjs@npm:string-width@^4.2.0")).toMatchObject({ name: "string-width", version: "4.2.3" });
    expect(entries.get("@babel/core@^7.1.0")).toMatchObject({ name: "@babel/core", version: "7.24.0" });
  });

  it("finds the entry line for each format", () => {
    expect(lockfileLine("npm", ["{", '    "node_modules/lodash": {'], "lodash", "4.17.21")).toBe(2);
    expect(lockfileLine("pnpm", ["packages:", "  lodash@4.17.21:"], "lodash", "4.17.21")).toBe(2);
    expect(lockfileLine("yarn", ["  dependencies:", '    lodash "^4"', '"lodash@npm:^4.17.20":'], "lodash", "4.17.21")).toBe(3);
  });
});
