import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyEdits } from "../src/fix/edits.js";
import type { CompletionRequest, CompletionResult, LlmBackend } from "../src/llm/backend.js";
import { FileMemory, formatLessons, lessonFrom, type Lesson } from "../src/memory.js";
import { mitigateFinding } from "../src/mitigate.js";
import type { Finding } from "../src/types.js";

const lesson = (l: Partial<Lesson>): Lesson => ({
  ecosystem: "npm", package: "axios", from: "0.27.2", to: "1.7.4", kind: "upgrade", outcome: "fixed",
  summary: "interceptors now receive InternalAxiosRequestConfig", files: ["src/http.ts"], date: "2026-10-01", ...l,
});

const store = async () => new FileMemory(path.join(await mkdtemp(path.join(tmpdir(), "autofix-mem-")), "memory.json"));

afterEach(() => {
  delete process.env.AUTOFIX_MEMORY;
});

describe("FileMemory", () => {
  it("recalls lessons for the package, most relevant first", async () => {
    const m = await store();
    await m.record(lesson({ to: "0.28.0", date: "2026-10-05", summary: "minor bump" }));
    await m.record(lesson({ date: "2026-09-01" }));
    await m.record(lesson({ outcome: "failed", date: "2026-10-02", summary: "kept the old config type", failure: "tsc: Type error" }));
    await m.record(lesson({ package: "lodash", from: "4.17.20", to: "4.18.1" }));
    const found = await m.recall({ ecosystem: "npm", package: "axios", from: "0.27.2", to: "1.8.0", kind: "upgrade" });
    expect(found.map((l) => [l.to, l.outcome])).toEqual([
      ["1.7.4", "fixed"],
      ["1.7.4", "failed"],
      ["0.28.0", "fixed"],
    ]);
    expect(await m.recall({ ecosystem: "PyPI", package: "axios", from: "1.0" })).toEqual([]);
  });

  it("replaces a repeated attempt instead of piling up, and caps each package", async () => {
    const m = await store();
    await m.record(lesson({ summary: "old note", date: "2026-10-01" }));
    await m.record(lesson({ summary: "new note", date: "2026-10-02" }));
    expect((await m.recall({ ecosystem: "npm", package: "axios", from: "0.27.2" })).map((l) => l.summary)).toEqual(["new note"]);
    for (let i = 0; i < 25; i++) await m.record(lesson({ from: `0.${i}.0`, date: `2026-10-${String(i + 3).padStart(2, "0")}` }));
    expect(await m.recall({ ecosystem: "npm", package: "axios", from: "0.1.0" }, 100)).toHaveLength(20);
  });

  it("matches NuGet ids case-insensitively, and can live in a shared file", async () => {
    const shared = path.join(await mkdtemp(path.join(tmpdir(), "autofix-shared-")), "team.json");
    process.env.AUTOFIX_MEMORY = shared;
    const m = FileMemory.forProject("/any/project");
    expect(m.file).toBe(path.resolve(shared));
    await m.record(lesson({ ecosystem: "NuGet", package: "Newtonsoft.Json", from: "12.0.1", to: "13.0.1" }));
    expect(await m.recall({ ecosystem: "NuGet", package: "newtonsoft.json", from: "12.0.3" })).toHaveLength(1);
  });
});

describe("lessons", () => {
  const dep = { ecosystem: "npm" as const, name: "axios", version: "0.27.2" };

  it("are taken from what the run established, without manifests", () => {
    expect(
      lessonFrom(dep, { status: "fixed", strategy: "upgrade", to: "1.7.4", explanations: ["a", "b"], changedFiles: ["package.json", "package-lock.json", "src/http.ts", ".autofix-cve.json"] }, undefined, new Date("2026-10-28")),
    ).toEqual(lesson({ summary: "a Then: b", date: "2026-10-28" }));
    const failed = lessonFrom(dep, { status: "failed", strategy: "upgrade", to: "1.7.4", reason: "`npm test` still fails", explanations: ["tried x"], changedFiles: [] });
    expect(failed).toMatchObject({ outcome: "failed", summary: "tried x", failure: "`npm test` still fails", files: [] });
    expect(lessonFrom(dep, { status: "skipped", strategy: "none", changedFiles: [] })).toBeUndefined();
    expect(lessonFrom(dep, { status: "mitigated", explanation: "guard", changedFiles: ["app.js"] }, "mitigate")).toMatchObject({ kind: "mitigate", outcome: "fixed" });
    expect(lessonFrom(dep, { status: "not-applicable", changedFiles: [] }, "mitigate")).toBeUndefined();
  });

  it("are shown to the model as verified outcomes", () => {
    const text = formatLessons("axios", [lesson({}), lesson({ outcome: "failed", summary: "kept types", failure: "tsc error" })]);
    expect(text).toContain("What earlier runs in this repository learned about axios");
    expect(text).toContain("0.27.2 → 1.7.4: WORKED. interceptors now receive InternalAxiosRequestConfig (changed src/http.ts)");
    expect(text).toContain("FAILED and was rolled back. Tried: kept types. Why: tsc error");
    expect(formatLessons("axios", [])).toBe("");
  });

  it("reach the prompt, and the model cannot rewrite them", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-mem-mit-"));
    await writeFile(path.join(dir, "app.js"), "x");
    const m = new FileMemory(path.join(dir, ".autofix-cve", "memory.json"));
    await m.record(lesson({ package: "tmpl", from: "1.0.0", kind: "mitigate", summary: "reject <% in templates", to: undefined }));
    const prompts: string[] = [];
    const backend: LlmBackend = {
      async complete<T>(req: CompletionRequest): Promise<CompletionResult<T>> {
        prompts.push(req.prompt);
        return { output: { applicable: false, explanation: "n/a", residualRisk: "", edits: [] } as T, costUsd: 0 };
      },
    };
    const f = {
      dependency: { ecosystem: "npm", name: "tmpl", version: "1.0.0", paths: [], direct: true, dev: false, introducedBy: ["tmpl"] },
      vulns: [{ id: "GHSA-t", aliases: [], summary: "", details: "", fixedVersions: [], fixCommits: [] }],
      unfixable: ["GHSA-t"], breaking: false, via: [], reachability: "likely",
      usages: [{ file: "app.js", line: 1, column: 1, specifier: "tmpl", symbol: "template", snippet: "x", mentionedBy: [] }],
    } as Finding;
    await mitigateFinding(dir, f, { backend, checks: ["node -v"], maxAttempts: 1, log: () => {}, memory: m });
    expect(prompts[0]).toContain("WORKED. reject <% in templates");
    await expect(applyEdits(dir, [{ file: ".autofix-cve/memory.json", search: "", replace: "{}" }], new Map())).rejects.toThrow(/must not be edited/);
  });
});
