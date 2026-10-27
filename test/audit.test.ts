import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { auditEvent, auditing, defaultAuditPath, sha256, startAudit, stopAudit } from "../src/audit.js";
import { run } from "../src/fix/exec.js";
import { AuditBackend, type CompletionRequest, type CompletionResult, type LlmBackend } from "../src/llm/backend.js";

const lines = async (file: string) => (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l));

class Echo implements LlmBackend {
  async complete<T>(req: CompletionRequest): Promise<CompletionResult<T>> {
    if (req.prompt === "fail") throw new Error("model down");
    return { output: { edits: [{ file: "a.js", search: "x", replace: "y" }] } as T, costUsd: 0.02 };
  }
}

describe("audit log", () => {
  it("records nothing until started", async () => {
    expect(auditing()).toBe(false);
    auditEvent("ignored", {});
    expect(defaultAuditPath("/p", "fix", new Date("2026-10-27T01:02:03.004Z"))).toBe(path.join("/p", ".autofix-cve", "audit", "fix-2026-10-27T01-02-03-004Z.jsonl"));
  });

  it("writes one JSON line per command, model call and result, in order", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-audit-"));
    const file = startAudit(path.join(dir, "nested", "run.jsonl"), { command: "fix", projectDir: dir });
    await run('node -e "console.log(42)"', dir);
    const backend = new AuditBackend(new Echo());
    await backend.complete({ system: "sys", prompt: "secret source code", schema: {} });
    await expect(backend.complete({ system: "sys", prompt: "fail", schema: {} })).rejects.toThrow("model down");
    auditEvent("results", { fixed: 1 });
    stopAudit({ exitCode: 0 });
    expect(auditing()).toBe(false);

    const events = await lines(file);
    expect(events.map((e) => e.type)).toEqual(["start", "command", "model", "model", "results", "end"]);
    expect(new Set(events.map((e) => e.run)).size).toBe(1);
    expect(events[1]).toMatchObject({ command: 'node -e "console.log(42)"', exitCode: 0, ok: true });
    expect(events[1].output.trim()).toBe("42");
    // The prompt (project source) is kept as a hash; the reply, which is what gets applied, in full.
    expect(events[2]).toMatchObject({ ok: true, costUsd: 0.02, promptSha256: sha256("secret source code"), promptChars: 18 });
    expect(JSON.stringify(events[2])).not.toContain("secret source code");
    expect(events[2].output.edits[0]).toEqual({ file: "a.js", search: "x", replace: "y" });
    expect(events[3]).toMatchObject({ ok: false, error: "model down" });
  });
});
