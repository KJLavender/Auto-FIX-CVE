import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { checkScope, enforceScope, scopeSnapshot } from "../src/scope.js";

async function repo(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "autofix-scope-"));
  const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q");
  await mkdir(path.join(dir, "src"));
  await writeFile(path.join(dir, "package.json"), '{"dependencies":{"a":"1.0.0"}}\n');
  await writeFile(path.join(dir, "src", "app.js"), "module.exports = 1;\n");
  await writeFile(path.join(dir, "notes.txt"), "committed\n");
  git("add", "-A");
  git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base");
  return dir;
}

const p = (dir: string, ...parts: string[]) => path.join(dir, ...parts);
// git may check files out with CRLF (core.autocrlf on Windows).
const read = async (file: string) => (await readFile(file, "utf8")).replaceAll(String.fromCharCode(13), "");
const result = (changedFiles: string[]) => ({ status: "fixed", changedFiles, reason: undefined as string | undefined });

describe("scope validation", () => {
  it("accepts changes the fix declared, and notes untracked build output", async () => {
    const dir = await repo();
    const snap = (await scopeSnapshot(dir))!;
    await writeFile(p(dir, "package.json"), '{"dependencies":{"a":"1.0.1"}}\n');
    await writeFile(p(dir, "src", "app.js"), "module.exports = 2;\n");
    await mkdir(p(dir, "dist"));
    await writeFile(p(dir, "dist", "app.js"), "built");
    await mkdir(p(dir, ".autofix-cve"));
    await writeFile(p(dir, ".autofix-cve", "x.json"), "{}");
    const scope = await checkScope(snap, [p(dir, "package.json"), p(dir, "src", "app.js")], [p(dir, ".autofix-cve")]);
    expect(scope.violations).toEqual([]);
    expect(scope.notes).toEqual(["dist/app.js"]);
  });

  it("rolls back everything when a tracked file or a sensitive place changes outside the fix", async () => {
    const dir = await repo();
    // Uncommitted work from before the run must survive the rollback.
    await writeFile(p(dir, "notes.txt"), "my local edit\n");
    const snap = await scopeSnapshot(dir);
    await writeFile(p(dir, "package.json"), '{"dependencies":{"a":"1.0.1"}}\n');
    await writeFile(p(dir, "src", "app.js"), "require('child_process').exec('curl evil');\n");
    await mkdir(p(dir, ".github", "workflows"), { recursive: true });
    await writeFile(p(dir, ".github", "workflows", "x.yml"), "on: push");
    let resynced = false;
    const r = await enforceScope(dir, snap, result(["package.json"]), "fixed", ["package.json"], [], async () => {
      resynced = true;
    });
    expect(r.status).toBe("failed");
    expect(r.reason).toMatch(/fail-closed: .*\.github\/workflows\/x\.yml/);
    expect(r.reason).toMatch(/src\/app\.js/);
    expect(resynced).toBe(true);
    expect(await read(p(dir, "package.json"))).toBe('{"dependencies":{"a":"1.0.0"}}\n');
    expect(await read(p(dir, "src", "app.js"))).toBe("module.exports = 1;\n");
    expect(existsSync(p(dir, ".github", "workflows", "x.yml"))).toBe(false);
    expect(await read(p(dir, "notes.txt"))).toBe("my local edit\n");
  });

  it("honours --allow-changes, leaves failures alone, and skips outside git", async () => {
    const dir = await repo();
    const snap = await scopeSnapshot(dir);
    await writeFile(p(dir, "notes.txt"), "regenerated\n");
    expect((await enforceScope(dir, snap, result([]), "fixed", [], ["notes.txt"])).status).toBe("fixed");
    expect((await enforceScope(dir, snap, { ...result([]), status: "failed" }, "fixed", [], [])).status).toBe("failed");
    const plain = await mkdtemp(path.join(tmpdir(), "autofix-nogit-"));
    expect(await scopeSnapshot(plain)).toBeUndefined();
  });
});
