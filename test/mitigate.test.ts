import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { activeMitigations, readManifest } from "../src/backport/manifest.js";
import type { CompletionRequest, CompletionResult, LlmBackend } from "../src/llm/backend.js";
import { mitigateFinding, mitigationCandidates } from "../src/mitigate.js";
import type { Finding, Vulnerability } from "../src/types.js";
import { vexStatements } from "../src/vex.js";

const SOURCE = 'const _ = { template: (t) => () => t };\nfunction render(t) {\n  return _.template(t)();\n}\nmodule.exports = { render };\n';
const GUARD = "  if (/<%/.test(t)) throw new Error(\"templates may not contain code\");\n  return _.template(t)();";

/** Replies in order; records the prompts it was given. */
class FakeBackend implements LlmBackend {
  prompts: string[] = [];
  constructor(private readonly replies: unknown[]) {}
  async complete<T>(req: CompletionRequest): Promise<CompletionResult<T>> {
    this.prompts.push(req.prompt);
    return { output: this.replies.shift() as T, costUsd: 0.01 };
  }
}

const vuln: Vulnerability = {
  id: "GHSA-test",
  aliases: ["CVE-2026-0001"],
  summary: "Code injection via template",
  details: "Untrusted templates containing <% %> run code.",
  fixedVersions: [],
  fixCommits: [],
};

function finding(): Finding {
  return {
    dependency: { ecosystem: "npm", name: "tmpl", version: "1.0.0", paths: [], direct: true, dev: false, introducedBy: ["tmpl"] },
    vulns: [vuln],
    unfixable: [vuln.id],
    breaking: false,
    usages: [{ file: "app.js", line: 3, column: 10, specifier: "tmpl", symbol: "template", snippet: "return _.template(t)();", mentionedBy: [vuln.id] }],
    via: [],
    reachability: "likely",
  };
}

async function project(): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "autofix-mitigate-"));
  await writeFile(path.join(dir, "app.js"), SOURCE);
  return dir;
}

const CHECK = 'node -e "const { render } = require(\'./app.js\'); if (render(\'hi\') !== \'hi\') process.exit(1)"';
const guardEdit = { file: "app.js", search: "  return _.template(t)();", replace: GUARD };
const opts = (backend: LlmBackend, checks = [CHECK]) => ({ backend, checks, maxAttempts: 2, log: () => {} });

describe("mitigate", () => {
  it("only offers packages with no fixed release that the code calls", () => {
    const fixable = { ...finding(), safeVersion: "2.0.0", unfixable: [] };
    const unused = { ...finding(), usages: [] };
    expect(mitigationCandidates([finding(), fixable, unused])).toHaveLength(1);
  });

  it("applies guards that pass the checks and records them while they stay in the code", async () => {
    const dir = await project();
    const backend = new FakeBackend([{ applicable: true, explanation: "rejects templates with code", residualRisk: "none known", edits: [guardEdit] }]);
    const r = await mitigateFinding(dir, finding(), opts(backend));
    expect(r).toMatchObject({ status: "mitigated", attempts: 1, changedFiles: ["app.js", ".autofix-cve.json"] });
    expect(await readFile(path.join(dir, "app.js"), "utf8")).toContain("templates may not contain code");
    expect(backend.prompts[0]).toContain("app.js:3 `template` (named in the advisory)");

    const manifest = await readManifest(dir);
    expect(manifest.mitigations?.[0]).toMatchObject({ package: "tmpl", version: "1.0.0", vulns: ["GHSA-test"], guards: [{ file: "app.js", code: GUARD }] });
    expect(await activeMitigations(dir, manifest)).toHaveLength(1);
    // Edited away: no longer counts.
    await writeFile(path.join(dir, "app.js"), SOURCE);
    expect(await activeMitigations(dir, manifest)).toHaveLength(0);
  });

  it("rolls back guards that break the checks and retries with the failure", async () => {
    const dir = await project();
    const broken = { file: "app.js", search: "  return _.template(t)();", replace: "  return undefined;" };
    const backend = new FakeBackend([
      { applicable: true, explanation: "too strict", residualRisk: "", edits: [broken] },
      { applicable: true, explanation: "rejects templates with code", residualRisk: "none known", edits: [guardEdit] },
    ]);
    const r = await mitigateFinding(dir, finding(), opts(backend));
    expect(r).toMatchObject({ status: "mitigated", attempts: 2 });
    expect(backend.prompts[1]).toContain("Previous attempts (rolled back)");
    expect(r.costUsd).toBeCloseTo(0.02);
  });

  it("leaves the code alone when no guard applies, or there is nothing to verify with", async () => {
    const dir = await project();
    const none = new FakeBackend([{ applicable: false, explanation: "input is a constant", residualRisk: "", edits: [] }]);
    expect(await mitigateFinding(dir, finding(), opts(none))).toMatchObject({ status: "not-applicable", reason: "input is a constant" });
    expect(await mitigateFinding(dir, finding(), opts(none, []))).toMatchObject({ status: "failed", reason: expect.stringMatching(/--check/) });
    expect(await readFile(path.join(dir, "app.js"), "utf8")).toBe(SOURCE);
    expect((await readManifest(dir)).mitigations).toBeUndefined();
  });

  it("never lets the model edit dependency files", async () => {
    const dir = await project();
    const sneaky = new FakeBackend([
      { applicable: true, explanation: "", residualRisk: "", edits: [{ file: "package.json", search: "", replace: "{}" }] },
      { applicable: true, explanation: "", residualRisk: "", edits: [{ file: "node_modules/tmpl/index.js", search: "", replace: "" }] },
    ]);
    const r = await mitigateFinding(dir, finding(), opts(sneaky));
    expect(r.status).toBe("failed");
    expect(sneaky.prompts[1]).toContain("must not be edited");
  });

  it("is stated in VEX as an inline mitigation", () => {
    const f = { ...finding(), mitigation: { vulns: ["GHSA-test"], explanation: "rejects templates with code", residualRisk: "none known", files: ["app.js"] } };
    const [st] = vexStatements({ findings: [f], ignored: [], backports: [] });
    expect(st).toMatchObject({ status: "not_affected", justification: "inline_mitigations_already_exist", vulnerability: { name: "CVE-2026-0001" } });
  });
});
