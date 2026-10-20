import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { canBackport } from "../backport/backport.js";
import { readNpmLockfile } from "../lockfile/npm.js";
import type { LlmBackend } from "../llm/backend.js";
import type { OsvClient } from "../osv/client.js";
import type { Finding } from "../types.js";
import { compareVersions } from "../versions.js";
import { changelogExcerpt, exportShape, relevantFiles } from "./context.js";
import { applyEdits, changedSince, restoreFiles, type Edit } from "./edits.js";
import { run, tail } from "./exec.js";

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
}

/** Decides what `fix` would do for a finding, without touching anything. */
export function planFinding(finding: Finding, policy: PlanPolicy): PlanStep {
  const dep = finding.dependency;
  const to = finding.safeVersion;
  const backportable = policy.backport && canBackport(finding);
  const skip = (reason: string): PlanStep => ({ finding, action: "skip", reason });
  const backportOr = (reason: string, why: string): PlanStep =>
    backportable ? { finding, action: "backport", reason: why } : skip(`${reason}; no backport possible`);

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
    fixedVulns: finding.vulns.filter((v) => !finding.unfixable.includes(v.id)).map(describeVuln),
    evidence: [],
    costUsd: 0,
  };
  const step = planFinding(finding, opts);
  if (step.action === "skip" || step.action === "backport") return { ...result, reason: step.reason };
  const to = finding.safeVersion!;

  const pkgPath = path.join(projectDir, "package.json");
  const lockPath = path.join(projectDir, "package-lock.json");
  const originals = new Map<string, string | null>();
  originals.set(pkgPath, await readFile(pkgPath, "utf8"));
  originals.set(lockPath, existsSync(lockPath) ? await readFile(lockPath, "utf8") : null);

  const pkgText = originals.get(pkgPath)!;
  const pkg = JSON.parse(pkgText) as Record<string, unknown> & { overrides?: Record<string, string> };
  const field = DEP_FIELDS.find((f) => (pkg[f] as Record<string, string> | undefined)?.[dep.name] !== undefined);

  const direct = step.action === "upgrade" && field !== undefined;
  const writePkg = async (spec: string) => {
    if (direct) {
      (pkg[field] as Record<string, string>)[dep.name] = spec;
    } else {
      // Key the override on the exact vulnerable version, so other copies of the
      // package (e.g. an unrelated older major) are left alone.
      pkg.overrides = { ...pkg.overrides, [`${dep.name}@${dep.version}`]: spec };
    }
    await writeFile(pkgPath, JSON.stringify(pkg, null, detectIndent(pkgText)) + "\n", "utf8");
  };

  const rollback = async (reason: string): Promise<FixResult> => {
    opts.log(`  rolling back ${dep.name}: ${reason}`);
    await restoreFiles(originals);
    await run("npm install", projectDir);
    return { ...result, status: "failed", reason, changedFiles: [] };
  };

  result.strategy = direct ? "upgrade" : "override";
  const before = direct ? await exportShape(projectDir, dep.name) : "";
  const oldSpec = field ? (pkg[field] as Record<string, string>)[dep.name] : undefined;
  const prefix = oldSpec?.match(/^[\^~]/)?.[0] ?? "";

  opts.log(`  ${result.strategy} ${dep.name} ${dep.version} → ${to}`);
  await writePkg(prefix + to);
  let install = await run("npm install", projectDir);
  if (!install.ok) return rollback(`npm install failed:\n${tail(install.output, 2000)}`);

  // A caret range may resolve above the verified version; make sure that one is clean too.
  const installed = direct ? await readInstalledVersion(projectDir, dep.name) : to;
  if (installed && installed !== to) {
    const [ids] = await opts.osv.queryBatch([{ name: dep.name, version: installed }]);
    if (ids.length) {
      opts.log(`  ${dep.name}@${installed} is vulnerable (${ids.join(", ")}); pinning ${to}`);
      await writePkg(to);
      install = await run("npm install", projectDir);
      if (!install.ok) return rollback(`npm install failed:\n${tail(install.output, 2000)}`);
    }
  }
  const actual = (direct ? await readInstalledVersion(projectDir, dep.name) : to) ?? to;
  result.to = actual;

  // The lockfile must no longer resolve the vulnerable version anywhere.
  const stillThere = (await readNpmLockfile(projectDir)).some((d) => d.name === dep.name && d.version === dep.version);
  if (stillThere) return rollback(`${dep.name}@${dep.version} is still installed after the change`);

  const shapes = { before, after: direct ? await exportShape(projectDir, dep.name) : "" };
  const changelog = direct ? await changelogExcerpt(projectDir, dep.name, dep.version) : undefined;
  const history: string[] = [];

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
  return { ...result, status: "fixed", evidence, changedFiles: await changedSince(projectDir, originals) };
}
