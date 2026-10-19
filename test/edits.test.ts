import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { applyEdits } from "../src/fix/edits.js";

async function project(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "autofix-edits-"));
  for (const [f, c] of Object.entries(files)) await writeFile(path.join(dir, f), c);
  return dir;
}

describe("applyEdits", () => {
  it("replaces unique text and remembers the original", async () => {
    const dir = await project({ "a.js": 'const m = require("marked");\nm(x);\n' });
    const originals = new Map<string, string | null>();
    const changed = await applyEdits(dir, [{ file: "a.js", search: "m(x);", replace: "m.parse(x);" }], originals);
    expect(changed).toEqual(["a.js"]);
    expect(await readFile(path.join(dir, "a.js"), "utf8")).toContain("m.parse(x);");
    expect([...originals.values()]).toEqual(['const m = require("marked");\nm(x);\n']);
  });

  it("matches LF search text against CRLF files", async () => {
    const dir = await project({ "a.js": "a();\r\nb();\r\n" });
    await applyEdits(dir, [{ file: "a.js", search: "a();\nb();", replace: "a();\nc();" }], new Map());
    expect(await readFile(path.join(dir, "a.js"), "utf8")).toBe("a();\r\nc();\r\n");
  });

  it("rejects ambiguous, missing and protected edits without writing anything", async () => {
    const dir = await project({ "a.js": "x();\nx();\n", "b.js": "y();\n" });
    const ok = { file: "b.js", search: "y();", replace: "z();" };
    await expect(applyEdits(dir, [ok, { file: "a.js", search: "x();", replace: "" }], new Map())).rejects.toThrow(/not unique/);
    await expect(applyEdits(dir, [{ file: "a.js", search: "nope", replace: "" }], new Map())).rejects.toThrow(/not found/);
    await expect(applyEdits(dir, [{ file: "package.json", search: "", replace: "{}" }], new Map())).rejects.toThrow(/must not/);
    await expect(applyEdits(dir, [{ file: "../evil.js", search: "", replace: "" }], new Map())).rejects.toThrow(/outside/);
    expect(await readFile(path.join(dir, "b.js"), "utf8")).toBe("y();\n");
  });
});
