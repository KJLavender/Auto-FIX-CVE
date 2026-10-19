import { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import semver from "semver";
import type { LlmBackend } from "../llm/backend.js";
import type { OsvClient } from "../osv/client.js";
import type { Finding } from "../types.js";
import { changelogExcerpt, exportShape, relevantFiles } from "./context.js";
import { applyEdits, type Edit } from "./edits.js";
import { run, tail } from "./exec.js";

export type FixStatus = "fixed" | "skipped" | "failed";

export interface FixResult {
  package: string;
  from: string;
  to?: string;
  strategy: "upgrade" | "override" | "none";
  status: FixStatus;
  reason?: string;
  /** LLM rounds used to repair the code after the upgrade. */
  attempts: number;
  changedFiles: string[];
  explanations: string[];
  costUsd: number;
}

export interface FixOptions {
  checks: string[];
  allowBreaking: boolean;
  maxAttempts: number;
  backend: LlmBackend;
  osv: OsvClient;
  log: (message: string) => void;
}

interface CheckResult {
  ok: boolean;
  command?: string;
  output: string;
}

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

const SYSTEM_PROMPT = `You are a senior engineer repairing a JavaScript/TypeScript project after a security-driven dependency upgrade.
Rules:
- Make the smallest source change that makes the failing command pass with the NEW version. Keep behaviour identical.
- Never downgrade or pin the dependency. Never edit package.json, lockfiles or node_modules.
- Do not delete, skip or weaken tests or assertions. Only change a test if it calls the upgraded library's API directly.
- Edits are exact search/replace operations: "search" must be copied verbatim from a file shown to you and occur exactly once in it, so include enough surrounding text. Use an empty "search" only to create a new file.
- If the failure is unrelated to the upgrade or cannot be fixed safely, return no edits and explain why.`;

const EDIT_SCHEMA = {
  type: "object",
  properties: {
    explanation: { type: "string", description: "What changed in the library and how the edits adapt to it." },
    edits: {
      type: "array",
      items: {
        type: "object",
        properties: {
          file: { type: "string", description: "Path relative to the project root, using forward slashes." },
          search: { type: "string" },
          replace: { type: "string" },
        },
        required: ["file", "search", "replace"],
      },
    },
  },
  required: ["explanation", "edits"],
};

async function runChecks(projectDir: string, checks: string[]): Promise<CheckResult> {
  for (const command of checks) {
    const res = await run(command, projectDir);
    if (!res.ok) return { ok: false, command, output: res.output };
  }
  return { ok: true, output: "" };
}

export async function verifyBaseline(projectDir: string, checks: string[]): Promise<void> {
  const res = await runChecks(projectDir, checks);
  if (!res.ok) {
    throw new Error(`\`${res.command}\` already fails before any change; fix it first.\n${tail(res.output, 3000)}`);
  }
}

function detectIndent(json: string): string | number {
  return json.match(/^[ \t]+(?=")/m)?.[0] ?? 2;
}

async function readInstalledVersion(projectDir: string, name: string): Promise<string | undefined> {
  const file = path.join(projectDir, "node_modules", name, "package.json");
  if (!existsSync(file)) return undefined;
  return (JSON.parse(await readFile(file, "utf8")) as { version: string }).version;
}

async function restore(originals: Map<string, string | null>): Promise<void> {
  for (const [abs, content] of originals) {
    if (content === null) await rm(abs, { force: true });
    else await writeFile(abs, content, "utf8");
  }
}

function buildPrompt(
  finding: Finding,
  to: string,
  failure: CheckResult,
  shapes: { before: string; after: string },
  changelog: string | undefined,
  history: string[],
  files: Map<string, string>,
): string {
  const { name, version } = finding.dependency;
  const parts: string[] = [];
  parts.push(`## Task\n\`${name}\` was upgraded from ${version} to ${to} to fix:`);
  for (const v of finding.vulns) {
    const cve = v.aliases.find((a) => a.startsWith("CVE-"));
    parts.push(`- ${v.id}${cve ? ` (${cve})` : ""}: ${v.summary}`);
  }
  parts.push(`\nAfter the upgrade, \`${failure.command}\` fails. Edit the source so it works with ${name}@${to}.`);
  parts.push(`\n## Failing output of \`${failure.command}\`\n\`\`\`\n${tail(failure.output)}\n\`\`\``);
  if (finding.usages.length) {
    parts.push(`\n## Where the project uses ${name}`);
    for (const u of finding.usages) parts.push(`- ${u.file}:${u.line} \`${u.symbol}\` — ${u.snippet}`);
  }
  parts.push(`\n## Runtime exports of ${name}\nBefore (${version}):\n${shapes.before}\nAfter (${to}):\n${shapes.after}`);
  if (changelog) parts.push(`\n## ${name} changelog (newest first, down to ${version})\n${changelog}`);
  if (history.length) parts.push(`\n## Previous attempts (did not fix it)\n${history.join("\n")}`);
  parts.push("\n## Files");
  for (const [file, content] of files) parts.push(`### ${file}\n\`\`\`\n${content}\n\`\`\``);
  return parts.join("\n");
}

export interface PlanStep {
  finding: Finding;
  action: "upgrade" | "override" | "skip";
  reason?: string;
}

export interface PlanPolicy {
  checks: string[];
  allowBreaking: boolean;
}

/** Decides what `fix` would do for a finding, without touching anything. */
export function planFinding(finding: Finding, policy: PlanPolicy): PlanStep {
  const dep = finding.dependency;
  const to = finding.safeVersion;
  const skip = (reason: string): PlanStep => ({ finding, action: "skip", reason });
  if (!to) return skip("no fixed version published; needs a backport");
  // Security fixes only ever move forward; a downgrade could reintroduce older bugs.
  if (!semver.gt(to, dep.version)) return skip(`refusing to move from ${dep.version} to ${to} (not an upgrade)`);
  if (!dep.direct && finding.breaking) {
    return skip(`transitive dependency needs a breaking upgrade (via ${dep.introducedBy.join(", ")}); needs a backport`);
  }
  if (finding.breaking && !policy.allowBreaking) return skip("breaking upgrade not allowed (--no-breaking)");
  if (finding.breaking && policy.checks.length === 0) {
    return skip("breaking upgrade but no build/test command to verify it; pass --check");
  }
  return { finding, action: dep.direct ? "upgrade" : "override" };
}

export async function fixFinding(projectDir: string, finding: Finding, opts: FixOptions): Promise<FixResult> {
  const dep = finding.dependency;
  const result: FixResult = {
    package: dep.name,
    from: dep.version,
    to: finding.safeVersion,
    strategy: "none",
    status: "skipped",
    attempts: 0,
    changedFiles: [],
    explanations: [],
    costUsd: 0,
  };
  const step = planFinding(finding, { checks: opts.checks, allowBreaking: opts.allowBreaking });
  if (step.action === "skip") return { ...result, reason: step.reason };
  const to = finding.safeVersion!;

  const pkgPath = path.join(projectDir, "package.json");
  const lockPath = path.join(projectDir, "package-lock.json");
  const originals = new Map<string, string | null>();
  originals.set(pkgPath, await readFile(pkgPath, "utf8"));
  originals.set(lockPath, existsSync(lockPath) ? await readFile(lockPath, "utf8") : null);

  const pkgText = originals.get(pkgPath)!;
  const pkg = JSON.parse(pkgText) as Record<string, unknown> & { overrides?: Record<string, string> };
  const field = DEP_FIELDS.find((f) => (pkg[f] as Record<string, string> | undefined)?.[dep.name] !== undefined);

  const writePkg = async (spec: string) => {
    if (dep.direct && field) {
      (pkg[field] as Record<string, string>)[dep.name] = spec;
    } else {
      pkg.overrides = { ...pkg.overrides, [dep.name]: spec };
    }
    await writeFile(pkgPath, JSON.stringify(pkg, null, detectIndent(pkgText)) + "\n", "utf8");
  };

  const rollback = async (reason: string): Promise<FixResult> => {
    opts.log(`  rolling back ${dep.name}: ${reason}`);
    await restore(originals);
    await run("npm install", projectDir);
    return { ...result, status: "failed", reason, changedFiles: [] };
  };

  result.strategy = step.action === "upgrade" && field ? "upgrade" : "override";
  const before = dep.direct ? await exportShape(projectDir, dep.name) : "";
  const oldSpec = field ? (pkg[field] as Record<string, string>)[dep.name] : undefined;
  const prefix = oldSpec?.match(/^[\^~]/)?.[0] ?? "";

  opts.log(`  ${result.strategy} ${dep.name} ${dep.version} → ${to}`);
  await writePkg(prefix + to);
  let install = await run("npm install", projectDir);
  if (!install.ok) return rollback(`npm install failed:\n${tail(install.output, 2000)}`);

  // A caret range may resolve above the verified version; make sure that one is clean too.
  const installed = await readInstalledVersion(projectDir, dep.name);
  if (installed && installed !== to) {
    const [ids] = await opts.osv.queryBatch([{ name: dep.name, version: installed }]);
    if (ids.length) {
      opts.log(`  ${dep.name}@${installed} is vulnerable (${ids.join(", ")}); pinning ${to}`);
      await writePkg(to);
      install = await run("npm install", projectDir);
      if (!install.ok) return rollback(`npm install failed:\n${tail(install.output, 2000)}`);
    }
  }
  const actual = (await readInstalledVersion(projectDir, dep.name)) ?? to;
  result.to = actual;

  const shapes = { before, after: dep.direct ? await exportShape(projectDir, dep.name) : "" };
  const changelog = dep.direct ? await changelogExcerpt(projectDir, dep.name, dep.version) : undefined;
  const history: string[] = [];
  const changed = new Set<string>();

  let check = await runChecks(projectDir, opts.checks);
  while (!check.ok) {
    if (result.attempts >= opts.maxAttempts) {
      return rollback(`\`${check.command}\` still fails after ${result.attempts} attempt(s)`);
    }
    result.attempts++;
    opts.log(`  \`${check.command}\` fails; asking the model for a fix (attempt ${result.attempts}/${opts.maxAttempts})`);

    const files = new Map<string, string>();
    for (const f of await relevantFiles(projectDir, finding.usages, check.output)) {
      files.set(f, await readFile(path.join(projectDir, f), "utf8"));
    }
    const prompt = buildPrompt(finding, actual, check, shapes, changelog, history, files);
    const { output, costUsd } = await opts.backend.complete<{ explanation: string; edits: Edit[] }>({
      system: SYSTEM_PROMPT,
      prompt,
      schema: EDIT_SCHEMA,
    });
    result.costUsd += costUsd;
    result.explanations.push(output.explanation);
    if (output.edits.length === 0) return rollback(`model declined to edit: ${output.explanation}`);

    try {
      for (const f of await applyEdits(projectDir, output.edits, originals)) changed.add(f);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      history.push(`- Attempt ${result.attempts}: edits could not be applied (${message}). Copy "search" text exactly.`);
      check = { ...check, output: `${check.output}\n[autofix-cve] previous edits rejected: ${message}` };
      continue;
    }
    history.push(`- Attempt ${result.attempts}: ${output.explanation} (edited ${output.edits.map((e) => e.file).join(", ")})`);
    check = await runChecks(projectDir, opts.checks);
  }

  return { ...result, status: "fixed", changedFiles: ["package.json", "package-lock.json", ...changed] };
}
