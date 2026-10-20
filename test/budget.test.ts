import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { PackageManager } from "../src/fix/managers.js";
import { fixFinding } from "../src/fix/upgrade.js";
import { BudgetBackend, BudgetExceededError, type CompletionRequest, type LlmBackend } from "../src/llm/backend.js";
import { OsvClient } from "../src/osv/client.js";
import type { Finding } from "../src/types.js";

class PricedBackend implements LlmBackend {
  calls = 0;
  async complete<T>(_req: CompletionRequest) {
    this.calls++;
    return { output: { explanation: "", edits: [] } as T, costUsd: 0.04 };
  }
}

describe("BudgetBackend", () => {
  it("refuses calls once the limit is reached", async () => {
    const inner = new PricedBackend();
    const budget = new BudgetBackend(inner, 0.1);
    await budget.complete({ system: "", prompt: "", schema: {} });
    await budget.complete({ system: "", prompt: "", schema: {} });
    await budget.complete({ system: "", prompt: "", schema: {} }); // 0.08 spent: still under the limit
    await expect(budget.complete({ system: "", prompt: "", schema: {} })).rejects.toBeInstanceOf(BudgetExceededError);
    expect(inner.calls).toBe(3);
    expect(budget.spentUsd).toBeCloseTo(0.12);
  });
});

/** A package manager that only edits a manifest file, so the upgrade loop can run without a registry. */
class FakeManager implements PackageManager {
  language = "JavaScript/TypeScript";
  canOverride = true;
  manifestFiles = ["manifest.txt"];
  constructor(private readonly dir: string) {}
  async declares() {
    return true;
  }
  async require(_dep: unknown, to: string) {
    await writeFile(path.join(this.dir, "manifest.txt"), `pkg@${to}\n`);
  }
  async install() {
    return { ok: true, output: "" };
  }
  async lockedVersions() {
    const text = await readFile(path.join(this.dir, "manifest.txt"), "utf8");
    return [text.trim().split("@")[1]];
  }
  async exportShape() {
    return "";
  }
  async changelog() {
    return undefined;
  }
  async sourceFiles() {
    return [];
  }
}

describe("fixFinding when the model is unavailable", () => {
  it("rolls back instead of leaving a half-done upgrade", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-budget-"));
    await writeFile(path.join(dir, "manifest.txt"), "pkg@1.0.0\n");
    const finding: Finding = {
      dependency: { ecosystem: "npm", name: "pkg", version: "1.0.0", paths: [], direct: true, dev: false, introducedBy: ["pkg"] },
      vulns: [],
      safeVersion: "2.0.0",
      unfixable: [],
      breaking: true,
      usages: [],
      via: [],
      reachability: "imported",
    };
    const exhausted = new BudgetBackend(new PricedBackend(), 0);
    const result = await fixFinding(dir, finding, {
      manager: new FakeManager(dir),
      checks: [`node -e "process.exit(1)"`], // the upgrade "breaks" the build, so the model is needed
      allowBreaking: true,
      backport: false,
      preferBackport: false,
      maxAttempts: 3,
      backend: exhausted,
      osv: new OsvClient(async () => undefined),
      log: () => {},
    });
    expect(result.status).toBe("failed");
    expect(result.reason).toMatch(/model call failed: model budget of \$0\.00 reached/);
    expect(await readFile(path.join(dir, "manifest.txt"), "utf8")).toBe("pkg@1.0.0\n");
  });
});
