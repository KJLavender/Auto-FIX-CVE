import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { canBackport } from "../backport/backport.js";
import { MANIFEST, removeBackport } from "../backport/manifest.js";
import { patchFileFor } from "../backport/replay.js";
import type { CompletionResult, LlmBackend } from "../llm/backend.js";
import type { OsvClient } from "../osv/client.js";
import type { Finding } from "../types.js";
import { compareVersions } from "../versions.js";
import { relevantFiles } from "./context.js";
import { applyEdits, changedSince, restoreFiles, snapshot, type Edit } from "./edits.js";
import { run, tail } from "./exec.js";
import type { PackageManager } from "./managers.js";

export type FixStatus = "fixed" | "skipped" | "failed";

export interface FixResult {
  package: string;
  from: string;
  to?: string;
  strategy: "upgrade" | "override" | "backport" | "none";
  status: FixStatus;
  reason?: string;
  /** LLM rounds used to repair the code after the upgrade. */
  attempts: number;
  changedFiles: string[];
  explanations: string[];
  /** Vulnerabilities this fix addresses, e.g. `GHSA-xxxx (CVE-2021-1234)`. */
  fixedVulns: string[];
  /** Human-readable proof that the fix works: checks run, PoC verdicts, rescans. */
  evidence: string[];
  costUsd: number;
}

export function describeVuln(v: { id: string; aliases: string[] }): string {
  const cve = v.aliases.find((a) => a.startsWith("CVE-"));
  return cve ? `${v.id} (${cve})` : v.id;
}

export interface FixOptions extends PlanPolicy {
  manager: PackageManager;
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

function systemPrompt(pm: PackageManager): string {
  return `You are a senior engineer repairing a ${pm.language} project after a security-driven dependency upgrade.
Rules:
- Make the smallest source change that makes the failing command pass with the NEW version. Keep behaviour identical.
- Never downgrade or pin the dependency. Never edit ${pm.manifestFiles.join(", ")}, other lockfiles or installed packages.
- Do not delete, skip or weaken tests or assertions. Only change a test if it calls the upgraded library's API directly.
- Edits are exact search/replace operations: "search" must be copied verbatim from a file shown to you and occur exactly once in it, so include enough surrounding text. Use an empty "search" only to create a new file.
- If the failure is unrelated to the upgrade or cannot be fixed safely, return no edits and explain why.`;
}

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

export async function readInstalledVersion(projectDir: string, name: string): Promise<string | undefined> {
  const file = path.join(projectDir, "node_modules", name, "package.json");
  if (!existsSync(file)) return undefined;
  return (JSON.parse(await readFile(file, "utf8")) as { version: string }).version;
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
  action: "upgrade" | "override" | "backport" | "skip";
  reason?: string;
}

export interface PlanPolicy {
  checks: string[];
  allowBreaking: boolean;
  /** Allow porting upstream fixes into the installed version. */
  backport: boolean;
  /** Backport instead of a breaking upgrade even when the upgrade is allowed. */
  preferBackport: boolean;
  /** Whether the package manager can force a transitive version (npm overrides, uv constraints). */
  canOverride?: boolean;
}

/** Decides what `fix` would do for a finding, without touching anything. */
export function planFinding(finding: Finding, policy: PlanPolicy): PlanStep {
  const dep = finding.dependency;
  const to = finding.safeVersion;
  const backportable = policy.backport && canBackport(finding);
  const skip = (reason: string): PlanStep => ({ finding, action: "skip", reason });
  const backportOr = (reason: string, why: string): PlanStep =>
    backportable ? { finding, action: "backport", reason: why } : skip(`${reason}; no backport possible`);

  if (finding.vulns.some((v) => v.malicious) && !to) {
    return skip("MALICIOUS package with no clean release: remove it from the project and rotate any secrets it could read");
  }
  if (!to) return backportOr("no fixed release", "no fixed release");
  // Security fixes only ever move forward; a downgrade could reintroduce older bugs.
  if (compareVersions(dep.ecosystem, to, dep.version) <= 0) return skip(`refusing to move from ${dep.version} to ${to} (not an upgrade)`);
  if (finding.breaking) {
    if (!dep.direct) return backportOr(`transitive, upgrade is breaking (via ${dep.introducedBy.join(", ")})`, "transitive breaking upgrade");
    if (!policy.allowBreaking) return backportOr("breaking upgrade not allowed (--no-breaking)", "breaking upgrade not allowed");
    if (policy.preferBackport && backportable) return { finding, action: "backport", reason: "--prefer-backport" };
    if (policy.checks.length === 0) {
      return backportOr("breaking upgrade with no build/test command to verify it (pass --check)", "no checks to verify an upgrade");
    }
  }
  if (!dep.direct && policy.canOverride === false) {
    return backportOr(`transitive (via ${dep.introducedBy.join(", ")}) and this package manager cannot override it`, "transitive, no override");
  }
  return { finding, action: dep.direct ? "upgrade" : "override" };
}

export async function fixFinding(projectDir: string, finding: Finding, opts: FixOptions): Promise<FixResult> {
  const dep = finding.dependency;
  const pm = opts.manager;
  const result: FixResult = {
    package: dep.name,
    from: dep.version,
    to: finding.safeVersion,
    strategy: "none",
    status: "skipped",
    attempts: 0,
    changedFiles: [],
    explanations: [],
    fixedVulns: finding.vulns.filter((v) => !finding.unfixable.includes(v.id)).map(describeVuln),
    evidence: [],
    costUsd: 0,
  };
  const step = planFinding(finding, opts);
  if (step.action === "skip" || step.action === "backport") return { ...result, reason: step.reason };
  const to = finding.safeVersion!;

  const originals = new Map<string, string | null>();
  for (const f of pm.manifestFiles) await snapshot(originals, path.join(projectDir, f));
  // A backport of the old version becomes stale once the package moves on.
  for (const f of [MANIFEST, patchFileFor(dep.name, dep.version)]) await snapshot(originals, path.join(projectDir, f));

  const rollback = async (reason: string): Promise<FixResult> => {
    opts.log(`  rolling back ${dep.name}: ${reason}`);
    await restoreFiles(originals);
    await pm.install();
    return { ...result, status: "failed", reason, changedFiles: [] };
  };

  const direct = step.action === "upgrade" && (await pm.declares(dep));
  result.strategy = direct ? "upgrade" : "override";
  const before = direct ? await pm.exportShape(dep.name) : "";

  opts.log(`  ${result.strategy} ${dep.name} ${dep.version} → ${to}`);
  await pm.require(dep, to, direct, false);
  let install = await pm.install();
  if (!install.ok) return rollback(`install failed:\n${tail(install.output, 2000)}`);

  // A range may resolve above the verified version; make sure what got locked is clean too.
  const locked = (await pm.lockedVersions(dep.name)).filter((v) => compareVersions(dep.ecosystem, v, dep.version) > 0);
  for (const v of locked.filter((v) => v !== to)) {
    const [ids] = await opts.osv.queryBatch([{ name: dep.name, version: v, ecosystem: dep.ecosystem }]);
    if (ids.length) {
      opts.log(`  ${dep.name}@${v} is vulnerable (${ids.join(", ")}); pinning ${to}`);
      await pm.require(dep, to, direct, true);
      install = await pm.install();
      if (!install.ok) return rollback(`install failed:\n${tail(install.output, 2000)}`);
      break;
    }
  }

  // Another package may still hold a nested copy of the old version. If the fix is
  // semver-compatible, override that copy too; a breaking one would break its consumer.
  if (direct && !finding.breaking && (await pm.lockedVersions(dep.name)).includes(dep.version)) {
    opts.log(`  ${dep.name}@${dep.version} is still pulled in by another package; overriding that copy too`);
    await pm.require(dep, to, false, false);
    install = await pm.install();
    if (!install.ok) return rollback(`install failed:\n${tail(install.output, 2000)}`);
  }

  // The lockfile must no longer resolve the vulnerable version anywhere.
  const versions = await pm.lockedVersions(dep.name);
  if (versions.includes(dep.version)) return rollback(`${dep.name}@${dep.version} is still locked after the change`);
  const actual = versions.find((v) => compareVersions(dep.ecosystem, v, dep.version) > 0) ?? to;
  result.to = actual;

  const shapes = { before, after: direct ? await pm.exportShape(dep.name) : "" };
  const changelog = direct ? await pm.changelog(dep.name, dep.version) : undefined;
  const sources = await pm.sourceFiles();
  const history: string[] = [];

  let check = await runChecks(projectDir, opts.checks);
  while (!check.ok) {
    if (result.attempts >= opts.maxAttempts) {
      return rollback(`\`${check.command}\` still fails after ${result.attempts} attempt(s)`);
    }
    result.attempts++;
    opts.log(`  \`${check.command}\` fails; asking the model for a fix (attempt ${result.attempts}/${opts.maxAttempts})`);

    const files = new Map<string, string>();
    for (const f of await relevantFiles(projectDir, finding.usages, check.output, sources)) {
      files.set(f, await readFile(path.join(projectDir, f), "utf8"));
    }
    const prompt = buildPrompt(finding, actual, check, shapes, changelog, history, files);
    let reply: CompletionResult<{ explanation: string; edits: Edit[] }>;
    try {
      reply = await opts.backend.complete<{ explanation: string; edits: Edit[] }>({ system: systemPrompt(pm), prompt, schema: EDIT_SCHEMA });
    } catch (e) {
      // An unavailable model or an exhausted budget must not leave the project half-upgraded.
      return rollback(`model call failed: ${e instanceof Error ? e.message : e}`);
    }
    const { output, costUsd } = reply;
    result.costUsd += costUsd;
    result.explanations.push(output.explanation);
    if (output.edits.length === 0) return rollback(`model declined to edit: ${output.explanation}`);

    try {
      await applyEdits(projectDir, output.edits, originals);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      history.push(`- Attempt ${result.attempts}: edits could not be applied (${message}). Copy "search" text exactly.`);
      check = { ...check, output: `${check.output}\n[autofix-cve] previous edits rejected: ${message}` };
      continue;
    }
    history.push(`- Attempt ${result.attempts}: ${output.explanation} (edited ${output.edits.map((e) => e.file).join(", ")})`);
    check = await runChecks(projectDir, opts.checks);
  }

  const evidence = [
    `OSV reports no known vulnerabilities for ${dep.name}@${actual}`,
    opts.checks.length ? `checks pass after the upgrade: ${opts.checks.join(", ")}` : "no checks configured (semver-compatible upgrade)",
  ];
  if (result.attempts) evidence.push(`code repaired by the model in ${result.attempts} round(s)`);
  if (finding.unfixable.length) evidence.push(`still open, no fixed release exists yet: ${finding.unfixable.join(", ")}`);
  if (direct) await removeBackport(projectDir, dep.name, dep.version);
  return { ...result, status: "fixed", evidence, changedFiles: await changedSince(projectDir, originals) };
}
