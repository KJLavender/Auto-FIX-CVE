import { readFile } from "node:fs/promises";
import path from "node:path";
import { addMitigation, type MitigationRecord } from "./backport/manifest.js";
import { applyEdits, changedSince, restoreFiles, type Edit } from "./fix/edits.js";
import { run, tail } from "./fix/exec.js";
import { describeVuln } from "./fix/upgrade.js";
import type { LlmBackend } from "./llm/backend.js";
import type { Finding, Usage, Vulnerability } from "./types.js";

/** Vulnerabilities in a finding that no release fixes yet: the ones mitigation is for. */
export function unfixedVulns(f: Finding): Vulnerability[] {
  return f.safeVersion ? f.vulns.filter((v) => f.unfixable.includes(v.id)) : f.vulns;
}

/** Call sites the project itself controls: its own uses, and its uses of the package that pulls a transitive one in. */
export function callSites(f: Finding): Usage[] {
  return [...f.usages, ...f.via.flatMap((v) => v.usages)];
}

/** Findings worth mitigating: something has no fixed release, and the code calls into it. */
export function mitigationCandidates(findings: Finding[]): Finding[] {
  // Guards at call sites cannot contain malware, which runs on install or import.
  return findings.filter((f) => unfixedVulns(f).length > 0 && callSites(f).length > 0 && !f.vulns.some((v) => v.malicious));
}

export interface MitigateResult {
  package: string;
  version: string;
  status: "mitigated" | "not-applicable" | "failed";
  vulns: string[];
  reason?: string;
  explanation?: string;
  residualRisk?: string;
  changedFiles: string[];
  attempts: number;
  costUsd: number;
}

export interface MitigateOptions {
  backend: LlmBackend;
  checks: string[];
  maxAttempts: number;
  log: (message: string) => void;
  /** Source files the model may see, besides the call sites' files. */
  maxFiles?: number;
}

const SYSTEM = `You are an application security engineer. A dependency has vulnerabilities with NO fixed release, so it cannot be upgraded. Reduce the risk in the project's OWN code, at the call sites shown, until a fix ships.
Good mitigations: validate or reject untrusted input before it reaches the vulnerable API (type, length, allowed characters, allow-lists), cap sizes and depths, strip dangerous keys (e.g. __proto__), avoid the vulnerable option or switch to a safe API of the same library, fail closed.
Rules:
- Only guard against what the advisory describes. Legitimate inputs must behave exactly as before.
- Never edit dependency manifests, lockfiles, installed packages or vendored code. Do not delete, skip or weaken tests.
- Edits are exact search/replace operations: "search" must be copied verbatim from a file shown to you and occur exactly once in it. Use an empty "search" only to create a new file.
- If the advisory gives nothing concrete to guard against at these call sites, or the input is not attacker-controlled, return applicable=false and no edits. Do not invent a mitigation.
- residualRisk must say honestly what an attacker could still do.`;

const SCHEMA = {
  type: "object",
  properties: {
    applicable: { type: "boolean", description: "Whether a call-site guard meaningfully reduces the risk." },
    explanation: { type: "string", description: "What the guards block and why that is the advisory's trigger." },
    residualRisk: { type: "string", description: "What remains exploitable even with the guards." },
    edits: {
      type: "array",
      items: {
        type: "object",
        properties: { file: { type: "string" }, search: { type: "string" }, replace: { type: "string" } },
        required: ["file", "search", "replace"],
      },
    },
  },
  required: ["applicable", "explanation", "residualRisk", "edits"],
};

interface Reply {
  applicable: boolean;
  explanation: string;
  residualRisk: string;
  edits: Edit[];
}

function buildPrompt(f: Finding, vulns: Vulnerability[], files: Map<string, string>, history: string[]): string {
  const d = f.dependency;
  const parts = [`## Package\n\`${d.name}@${d.version}\` (${d.ecosystem}), ${d.direct ? "a direct dependency" : `pulled in by ${d.introducedBy.join(", ")}`}.`];
  parts.push("\n## Vulnerabilities without a fixed release");
  for (const v of vulns) parts.push(`### ${describeVuln(v)}: ${v.summary}\n${v.details.slice(0, 2500)}`);
  parts.push("\n## Call sites in this project");
  for (const u of callSites(f)) parts.push(`- ${u.file}:${u.line} \`${u.symbol}\`${u.mentionedBy.length ? " (named in the advisory)" : ""}: ${u.snippet}`);
  if (history.length) parts.push(`\n## Previous attempts (rolled back)\n${history.join("\n")}`);
  parts.push("\n## Files");
  for (const [file, content] of files) parts.push(`### ${file}\n\`\`\`\n${content}\n\`\`\``);
  return parts.join("\n");
}

async function runChecks(projectDir: string, checks: string[]): Promise<{ ok: boolean; command?: string; output: string }> {
  for (const command of checks) {
    const res = await run(command, projectDir);
    if (!res.ok) return { ok: false, command, output: res.output };
  }
  return { ok: true, output: "" };
}

/**
 * Asks the model for guards at the call sites, applies them and runs the
 * project's checks; anything that fails is rolled back, and a failing check
 * gets another round with the output. A mitigation that holds is recorded in
 * .autofix-cve.json with the code it added.
 */
export async function mitigateFinding(projectDir: string, f: Finding, opts: MitigateOptions): Promise<MitigateResult> {
  const vulns = unfixedVulns(f);
  const result: MitigateResult = {
    package: f.dependency.name,
    version: f.dependency.version,
    status: "failed",
    vulns: vulns.map(describeVuln),
    changedFiles: [],
    attempts: 0,
    costUsd: 0,
  };
  if (opts.checks.length === 0) return { ...result, reason: "no build/test command to verify the guards (pass --check)" };

  const fileNames = [...new Set(callSites(f).map((u) => u.file))].slice(0, opts.maxFiles ?? 8);
  const files = new Map<string, string>();
  for (const file of fileNames) files.set(file, await readFile(path.join(projectDir, file), "utf8"));

  const history: string[] = [];
  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    result.attempts = attempt;
    let reply: Reply;
    try {
      const res = await opts.backend.complete<Reply>({ system: SYSTEM, prompt: buildPrompt(f, vulns, files, history), schema: SCHEMA });
      result.costUsd += res.costUsd;
      reply = res.output;
    } catch (e) {
      return { ...result, reason: `model call failed: ${(e as Error).message}` };
    }
    if (!reply.applicable || reply.edits.length === 0) {
      return { ...result, status: "not-applicable", reason: reply.explanation, explanation: reply.explanation, residualRisk: reply.residualRisk };
    }

    const originals = new Map<string, string | null>();
    try {
      await applyEdits(projectDir, reply.edits, originals);
    } catch (e) {
      await restoreFiles(originals);
      history.push(`- Attempt ${attempt}: edits could not be applied (${(e as Error).message}).`);
      continue;
    }
    opts.log(`  guards applied (attempt ${attempt}); running checks`);
    const check = await runChecks(projectDir, opts.checks);
    if (!check.ok) {
      await restoreFiles(originals);
      history.push(`- Attempt ${attempt}: \`${check.command}\` failed after the edits:\n\`\`\`\n${tail(check.output, 3000)}\n\`\`\``);
      continue;
    }

    const changed = await changedSince(projectDir, originals);
    const record: MitigationRecord = {
      package: f.dependency.name,
      version: f.dependency.version,
      vulns: vulns.map((v) => v.id),
      guards: reply.edits.filter((e) => e.replace.trim()).map((e) => ({ file: e.file, code: e.replace })),
      explanation: reply.explanation,
      residualRisk: reply.residualRisk,
      date: new Date().toISOString().slice(0, 10),
    };
    await addMitigation(projectDir, record);
    return {
      ...result,
      status: "mitigated",
      explanation: reply.explanation,
      residualRisk: reply.residualRisk,
      changedFiles: [...changed, ".autofix-cve.json"],
    };
  }
  return { ...result, reason: `checks still failed after ${opts.maxAttempts} attempt(s); everything was rolled back` };
}
