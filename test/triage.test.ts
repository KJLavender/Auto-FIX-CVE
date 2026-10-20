import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { CompletionRequest, LlmBackend } from "../src/llm/backend.js";
import { fails } from "../src/scan.js";
import { buildTriagePrompt, triageFindings } from "../src/triage.js";
import type { Finding, Triage } from "../src/types.js";

const base: Finding = {
  dependency: { ecosystem: "PyPI", name: "pyyaml", version: "5.3.1", paths: [], direct: true, dev: false, introducedBy: ["pyyaml"] },
  vulns: [{ id: "GHSA-8q59-q68h-6hv4", aliases: ["CVE-2020-14343"], summary: "Arbitrary code execution in FullLoader", details: "", severity: "CRITICAL", fixedVersions: ["5.4"], fixCommits: [] }],
  safeVersion: "5.4",
  unfixable: [],
  breaking: false,
  usages: [{ file: "app/render.py", line: 4, column: 12, specifier: "yaml", symbol: "load", snippet: "", mentionedBy: [] }],
  via: [],
  reachability: "likely",
};

class FakeBackend implements LlmBackend {
  prompts: string[] = [];
  constructor(private readonly verdict: Triage) {}
  async complete<T>(req: CompletionRequest) {
    this.prompts.push(req.prompt);
    return { output: this.verdict as T, costUsd: 0.01 };
  }
}

describe("triage", () => {
  it("shows the model the advisory and the numbered code around each call site", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-triage-"));
    await mkdir(path.join(dir, "app"));
    await writeFile(path.join(dir, "app/render.py"), "import yaml\n\ndef load(text):\n    return yaml.load(text, Loader=yaml.FullLoader)\n");
    const backend = new FakeBackend({ verdict: "unclear", reasoning: "depends on input", conditions: "untrusted YAML" });
    const untouched: Finding = { ...base, dependency: { ...base.dependency, name: "pytest" }, usages: [], reachability: "not-imported" };
    const findings = [{ ...base }, untouched];

    const cost = await triageFindings(dir, findings, backend, 10, () => {});
    expect(cost).toBe(0.01);
    expect(backend.prompts).toHaveLength(1); // nothing to reason about for an unused package
    expect(backend.prompts[0]).toContain("CVE-2020-14343");
    expect(backend.prompts[0]).toContain("    4>     return yaml.load(text, Loader=yaml.FullLoader)");
    expect(findings[0].triage?.verdict).toBe("unclear");
    expect(untouched.triage).toBeUndefined();
  });

  it("tells the model when a transitive package is only reached through another one", () => {
    const prompt = buildTriagePrompt(
      { ...base, dependency: { ...base.dependency, name: "urllib3", direct: false, introducedBy: ["requests"] }, via: [{ package: "requests", usages: [] }] },
      [],
    );
    expect(prompt).toContain("transitive via requests");
    expect(prompt).toContain("reaches it through requests");
  });

  it("lets definite verdicts override the heuristic in --fail-on likely", () => {
    const withVerdict = (verdict: Triage["verdict"]): Finding => ({ ...base, triage: { verdict, reasoning: "", conditions: "" } });
    expect(fails(withVerdict("not-reachable"), "likely")).toBe(false);
    expect(fails(withVerdict("unclear"), "likely")).toBe(true);
    expect(fails({ ...withVerdict("reachable"), reachability: "imported" }, "likely")).toBe(true);
    expect(fails({ ...base, reachability: "imported" }, "likely")).toBe(false);
  });
});
