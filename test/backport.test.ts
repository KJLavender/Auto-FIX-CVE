import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { removedLines, splitDiff } from "../src/backport/github.js";
import { anchorsFor, locateTargets } from "../src/backport/locate.js";
import { APPLY_SCRIPT, ensurePostinstall, patchApplied, writePatch } from "../src/backport/replay.js";

const DIFF = `diff --git a/src/rules.js b/src/rules.js
--- a/src/rules.js
+++ b/src/rules.js
@@ -1,3 +1,3 @@
-  def: /^ {0,3}\\[(label)\\]: *\\n? *<?([^\\s>]+)>?/,
+  def: /^ {0,3}\\[(label)\\]: *(?:\\n *)?<?([^\\s>]+)>?/,
   text: /^[^\\n]+/
diff --git a/test/specs/redos/cubic_def.cjs b/test/specs/redos/cubic_def.cjs
--- /dev/null
+++ b/test/specs/redos/cubic_def.cjs
@@ -0,0 +1 @@
+module.exports = { markdown: '[x]:' + ' '.repeat(1500) };
`;

async function tempProject(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "autofix-backport-"));
  await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "app", scripts: { postinstall: "echo hi" } }, null, 2));
  await mkdir(path.join(dir, "node_modules/lib/dist"), { recursive: true });
  await writeFile(path.join(dir, "node_modules/lib/package.json"), JSON.stringify({ name: "lib", version: "1.0.0" }));
  await writeFile(path.join(dir, "node_modules/lib/dist/index.js"), "const re = /a+b/;\nconst unsafe = true;\nmodule.exports = re;\n");
  return dir;
}

describe("diff helpers", () => {
  it("separates library code from upstream tests", () => {
    const { code, tests } = splitDiff(DIFF);
    expect(code).toContain("src/rules.js");
    expect(code).not.toContain("cubic_def");
    expect(tests).toContain("cubic_def");
  });

  it("extracts removed lines and whitespace-free anchors for minified builds", () => {
    const removed = removedLines(splitDiff(DIFF).code);
    expect(removed).toEqual(["def: /^ {0,3}\\[(label)\\]: *\\n? *<?([^\\s>]+)>?/,"]);
    expect(anchorsFor(removed)).toContain("{0,3}\\[(label)\\]:");
  });
});

describe("locateTargets", () => {
  it("finds every copy of the vulnerable code, including minified bundles", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-locate-"));
    await mkdir(path.join(dir, "lib"));
    await writeFile(path.join(dir, "src.js"), "x\n  def: /old-regex-here/,\ny\n");
    await writeFile(path.join(dir, "lib/bundle.min.js"), "a".repeat(3000) + "def:/old-regex-here/," + "b".repeat(3000));
    await writeFile(path.join(dir, "lib/other.js"), "unrelated\n");
    const targets = await locateTargets(dir, ["def: /old-regex-here/,"]);
    expect(targets.map((t) => t.file).sort()).toEqual(["lib/bundle.min.js", "src.js"]);
    const min = targets.find((t) => t.file === "lib/bundle.min.js")!;
    expect(min.excerpt.length).toBeLessThan(2000);
  });
});

describe("replay script", () => {
  const edits = [
    { file: "dist/index.js", search: "/a+b/", replace: "/a+?b/" },
    { file: "dist/index.js", search: "const unsafe = true;\n", replace: "" },
  ];

  it("re-applies patches idempotently and is detected as applied", async () => {
    const dir = await tempProject();
    const patch = await writePatch(dir, { package: "lib", version: "1.0.0", path: "node_modules/lib", edits });
    expect(await patchApplied(dir, patch)).toBe(false);

    const run = () => execFileSync(process.execPath, [path.join(dir, APPLY_SCRIPT)], { encoding: "utf8" });
    expect(run()).toContain("patched lib@1.0.0 (2 edits)");
    const once = await readFile(path.join(dir, "node_modules/lib/dist/index.js"), "utf8");
    expect(once).toBe("const re = /a+?b/;\nmodule.exports = re;\n");
    expect(run()).toBe("");
    expect(await readFile(path.join(dir, "node_modules/lib/dist/index.js"), "utf8")).toBe(once);
    expect(await patchApplied(dir, patch)).toBe(true);
  });

  it("skips a patch when the installed version changed", async () => {
    const dir = await tempProject();
    await writePatch(dir, { package: "lib", version: "0.9.0", path: "node_modules/lib", edits });
    const out = execFileSync(process.execPath, [path.join(dir, APPLY_SCRIPT)], { encoding: "utf8", stdio: "pipe" });
    expect(out).toBe("");
    expect(await readFile(path.join(dir, "node_modules/lib/dist/index.js"), "utf8")).toContain("/a+b/");
  });

  it("chains onto an existing postinstall exactly once", async () => {
    const dir = await tempProject();
    await ensurePostinstall(dir);
    await ensurePostinstall(dir);
    const pkg = JSON.parse(await readFile(path.join(dir, "package.json"), "utf8"));
    expect(pkg.scripts.postinstall).toBe(`echo hi && node ${APPLY_SCRIPT}`);
  });
});
