import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { readNpmLockfile } from "../src/lockfile/npm.js";

async function withLock(lock: object): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "autofix-cve-"));
  await writeFile(path.join(dir, "package-lock.json"), JSON.stringify(lock));
  return dir;
}

describe("readNpmLockfile", () => {
  it("tracks direct deps, nested copies and who introduced them", async () => {
    const dir = await withLock({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { a: "^1.0.0", "@s/b": "^2.0.0" }, devDependencies: { t: "^1.0.0" } },
        "node_modules/a": { version: "1.0.0", dependencies: { c: "^1.0.0" } },
        "node_modules/@s/b": { version: "2.0.0", dependencies: { c: "^2.0.0" } },
        "node_modules/@s/b/node_modules/c": { version: "2.0.0" },
        "node_modules/c": { version: "1.0.0" },
        "node_modules/t": { version: "1.0.0", dev: true },
      },
    });
    const deps = await readNpmLockfile(dir);
    const get = (name: string, version: string) => deps.find((d) => d.name === name && d.version === version);

    expect(get("a", "1.0.0")).toMatchObject({ direct: true, dev: false, introducedBy: ["a"] });
    expect(get("@s/b", "2.0.0")).toMatchObject({ direct: true, introducedBy: ["@s/b"] });
    expect(get("c", "1.0.0")).toMatchObject({ direct: false, introducedBy: ["a"] });
    expect(get("c", "2.0.0")).toMatchObject({ direct: false, introducedBy: ["@s/b"] });
    expect(get("t", "1.0.0")).toMatchObject({ direct: true, dev: true });
  });

  it("rejects lockfile v1", async () => {
    const dir = await withLock({ lockfileVersion: 1, dependencies: {} });
    await expect(readNpmLockfile(dir)).rejects.toThrow(/lockfileVersion 1/);
  });
});
