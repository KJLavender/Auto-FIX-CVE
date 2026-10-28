#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { Command, Option } from "commander";
import pc from "picocolors";
import { backportFinding, canBackport } from "./backport/backport.js";
import { appliedBackports, MANIFEST, readManifest, ruleActive } from "./backport/manifest.js";
import { runPoc } from "./backport/poc.js";
import { readBaseline, splitByBaseline, writeBaseline } from "./baseline.js";
import { checkTools } from "./doctor.js";
import { endpoints } from "./endpoints.js";
import { applyRuntimeEdits, formatRuntimeReport, runtimeFails, scanRuntimes } from "./runtime/index.js";
import { detectChecks } from "./fix/context.js";
import { run } from "./fix/exec.js";
import { FIXABLE, managerFor } from "./fix/managers.js";
import { fixFinding, planFinding, readInstalledVersion, verifyBaseline, type FixResult } from "./fix/upgrade.js";
import { AuditBackend, BudgetBackend, createBackend, DEFAULT_MODEL, type LlmBackend } from "./llm/backend.js";
import { detectLockfiles, discoverProjects } from "./lockfile/index.js";
import { OsvClient } from "./osv/client.js";
import { abandonBranch, checkPrPrerequisites, createBranch, openPr } from "./pr.js";
import { formatFixSummary, formatPlan, formatReport, severityBreakdown } from "./report.js";
import { correlate, formatUpstreamGroups, type Exposure } from "./correlate.js";
import { callSites, mitigateFinding, mitigationCandidates, unfixedVulns, type MitigateResult } from "./mitigate.js";
import { toMarkdown } from "./markdown.js";
import { mergeSarif, toSarif, type SarifLog } from "./sarif.js";
import { triageFindings } from "./triage.js";
import { osDownloadList, readSbom } from "./sbom.js";
import { enforceScope, scopeSnapshot } from "./scope.js";
import { FileMemory, lessonFrom } from "./memory.js";
import { formatVet, parseSpec, vetPackage, type VetPolicy } from "./vet.js";
import { auditEvent, auditing, defaultAuditPath, startAudit, stopAudit } from "./audit.js";
import { openVex, vexStatements, type VexSources } from "./vex.js";
import { fails, mapLimit, scan, scanDependencies, type FailOn, type IgnoredVuln, type Severity } from "./scan.js";
import type { Finding } from "./types.js";

// dist/cli.js sits one level below package.json, so this works from a clone and from npx.
const VERSION = (createRequire(import.meta.url)("../package.json") as { version: string }).version;


async function confirm(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return /^y(es)?$/i.test((await rl.question(question)).trim());
  } finally {
    rl.close();
  }
}

interface ScanCliOptions {
  recursive?: boolean;
  json?: boolean;
  dev: boolean;
  maxUsages: number;
  sarif?: string;
  markdown?: string;
  baseline?: string;
  minSeverity?: Severity;
  updateBaseline?: boolean;
  failOn: FailOn;
  epssThreshold?: number;
  triage?: boolean;
  triageLimit: number;
  maxCost?: number;
  sbom?: string;
  vex?: string;
  vexProduct?: string;
  osList?: string;
}

/** Caps model spend when a limit is given; useful on a subscription or a large repo. */
function withBudget(backend: LlmBackend, maxCost: number | undefined): LlmBackend {
  // Every model call is recorded when an audit log is open.
  const audited = new AuditBackend(backend);
  return maxCost === undefined ? audited : new BudgetBackend(audited, maxCost);
}

/**
 * Opens the run's audit log (unless --no-audit) before anything changes, and
 * closes it when the process exits, whatever the outcome.
 */
/**
 * Whether the working tree has uncommitted changes, not counting this tool's
 * own records (`.autofix-cve/`: memory, audit logs), which a previous run leaves behind.
 */
async function uncommittedChanges(projectDir: string): Promise<boolean> {
  const status = await run("git status --porcelain", projectDir, 60_000, { trusted: true });
  if (!status.ok) return false;
  return status.output.split(/\r?\n/).some((line) => line.trim() && !/(^|\/)\.autofix-cve\//.test(line.slice(3).replace(/^"|"$/g, "")));
}

function openAudit(projectDir: string, command: string, opts: { audit?: boolean; auditLog?: string }, meta: Record<string, unknown>): string | undefined {
  if (opts.audit === false) return undefined;
  const file = startAudit(path.resolve(opts.auditLog ?? defaultAuditPath(projectDir, command)), {
    command,
    version: VERSION,
    args: process.argv.slice(2),
    projectDir,
    model: DEFAULT_MODEL,
    ...meta,
  });
  process.once("exit", () => {
    if (auditing()) stopAudit({ exitCode: process.exitCode ?? 0 });
  });
  return file;
}

/** A probability between 0 and 1, for --epss-threshold. */
function parseProbability(value: string): number {
  const p = Number.parseFloat(value);
  if (!(p >= 0 && p <= 1)) throw new Error(`--epss-threshold expects a number between 0 and 1, got ${value}`);
  return p;
}

const program = new Command();

program
  .name("autofix-cve")
  .description("Find CVEs in your dependencies, locate where your code uses them, and fix them.")
  .version(VERSION);

program
  .command("scan")
  .description("Scan a project's lockfiles for known vulnerabilities and map them to your code")
  .argument("[dir]", "project directory (npm, pnpm, Yarn, uv, Poetry, Pipenv or requirements.txt)", ".")
  .option("-r, --recursive", "also scan every project in subdirectories (monorepos)")
  .option("--json", "print machine-readable JSON")
  .option("--no-dev", "ignore dev-only dependencies")
  .option("--max-usages <n>", "usages to show per package", (v) => Number.parseInt(v, 10), 10)
  .option("--sarif <file>", "also write a SARIF 2.1.0 report (for GitHub code scanning)")
  .option("--markdown <file>", "also write a Markdown summary (for CI job summaries and PR comments)")
  .addOption(
    new Option("--min-severity <level>", "leave out vulnerabilities rated below this (unrated ones are kept)").choices([
      "low",
      "moderate",
      "high",
      "critical",
    ]),
  )
  .option("--baseline <file>", "only vulnerabilities not in this baseline count for --fail-on")
  .option("--update-baseline", "write the current vulnerabilities to the --baseline file and exit 0")
  .addOption(
    new Option(
      "--fail-on <level>",
      "exit 1 when findings match: any, likely (reachable), high (severity), risk (known exploited, or high and reachable), none",
    )
      .choices(["any", "likely", "high", "risk", "none"])
      .default("any"),
  )
  .option("--epss-threshold <p>", "with --fail-on risk: also fail on vulnerabilities whose EPSS score is at least this (0-1, e.g. 0.1)", parseProbability)
  .option("--triage", "ask the model whether each imported vulnerable package is reachable from your call sites")
  .option("--triage-limit <n>", "packages to triage at most, per project", (v) => Number.parseInt(v, 10), 10)
  .option("--max-cost <usd>", "stop triaging once this much has been spent on the model", (v) => Number.parseFloat(v))
  .option("--sbom <file>", "scan a CycloneDX or SPDX JSON SBOM (e.g. of a deployed image) instead of lockfiles")
  .option("--vex <file>", "also write an OpenVEX document: not-reachable triage verdicts, justified ignore rules, backports")
  .option("--vex-product <purl>", "with --vex: the product the packages ship in (e.g. pkg:oci/api@sha256:…), so statements name it")
  .option("--os-list <file>", "with --sbom: write pins for the fixed OS packages (apt/apk `name=version`, dnf `name-version`), for offline download")
  .action(async (dir: string, opts: ScanCliOptions) => {
    const root = path.resolve(dir);
    if (opts.osList && !opts.sbom) throw new Error("--os-list needs --sbom.");
    if (opts.sbom && (opts.sarif || opts.triage || opts.recursive)) {
      throw new Error("--sbom cannot be combined with --sarif, --triage or --recursive: an SBOM has no source code or lockfile lines.");
    }
    const projects = opts.sbom
      ? []
      : opts.recursive
        ? await discoverProjects(root)
        : detectLockfiles(root).map((lock) => ({ dir: root, lock }));
    if (projects.length === 0 && !opts.sbom) throw new Error(`No lockfile found in ${root}${opts.recursive ? " or below" : ""}.`);

    const log = (m: string) => console.error(pc.dim(m));
    // One budget across all projects of a recursive scan.
    const triageBackend = withBudget(createBackend(), opts.maxCost);
    const all: { project: string; lockfile: string; findings: Finding[]; sbom?: boolean }[] = [];
    const vexSources: VexSources = { findings: [], ignored: [], backports: [] };
    const logs: SarifLog[] = [];
    for (const { dir: projectDir, lock } of projects) {
      const label = path.relative(root, path.join(projectDir, lock.file)).split(path.sep).join("/");
      const ignored: IgnoredVuln[] = [];
      const findings = await scan(projectDir, { includeDev: opts.dev, lock, ignored, minSeverity: opts.minSeverity });
      if (opts.triage) {
        const cost = await triageFindings(projectDir, findings, triageBackend, opts.triageLimit, log);
        log(`Triage cost (${label}): $${cost.toFixed(4)}`);
      }
      if (opts.sarif) logs.push(await toSarif(projectDir, findings, VERSION, process.cwd(), lock));
      all.push({ project: path.relative(root, projectDir).split(path.sep).join("/") || ".", lockfile: label, findings });
      vexSources.findings.push(...findings);
      vexSources.ignored.push(...ignored);
      if (opts.vex) vexSources.backports.push(...(await appliedBackports(projectDir, await readManifest(projectDir))));

      if (opts.json) continue;
      if (projects.length > 1) console.log(pc.bold(pc.cyan(`\n== ${label} ==`)));
      console.log(formatReport(findings, opts.maxUsages));
      const manifest = await readManifest(projectDir);
      if (manifest.backports.length) {
        const applied = await appliedBackports(projectDir, manifest);
        for (const b of manifest.backports) {
          const status = applied.includes(b) ? pc.green("backported") : pc.red("backport NOT applied (run npm install)");
          console.log(`${status}  ${b.package}@${b.version}  ${pc.dim(b.vulns.join(", "))}`);
        }
      }
      for (const i of ignored) {
        console.log(`${pc.dim("ignored")}  ${i.package}@${i.version} ${i.id}  ${pc.dim(`${i.reason}${i.until ? ` (until ${i.until})` : ""}`)}`);
      }
      for (const r of (manifest.ignore ?? []).filter((r) => !ruleActive(r))) {
        const why = r.reason?.trim() ? `expired on ${r.until}` : "has no reason";
        console.log(pc.yellow(`ignore rule for ${r.id}${r.package ? ` (${r.package})` : ""} ${why}; the vulnerability is reported again`));
      }
    }

    if (opts.sbom) {
      const { deps, skipped } = await readSbom(opts.sbom);
      const ignored: IgnoredVuln[] = [];
      // Accepted risks still come from the .autofix-cve.json in [dir].
      const findings = await scanDependencies(deps, root, { includeDev: true, ignored, minSeverity: opts.minSeverity });
      all.push({ project: ".", lockfile: path.basename(opts.sbom), findings, sbom: true });
      vexSources.findings.push(...findings);
      vexSources.ignored.push(...ignored);
      if (opts.osList) {
        const lines = osDownloadList(findings);
        await writeFile(opts.osList, lines.map((l) => `${l}\n`).join(""), "utf8");
        console.error(pc.dim(`Wrote ${lines.length} OS package pins to ${opts.osList}.`));
      }
      if (!opts.json) {
        console.log(formatReport(findings, opts.maxUsages, false));
        for (const i of ignored) console.log(`${pc.dim("ignored")}  ${i.package}@${i.version} ${i.id}  ${pc.dim(i.reason)}`);
        const other = Object.entries(skipped).map(([type, n]) => `${type} ${n}`);
        console.log(pc.dim(`Checked ${deps.length} packages from ${path.basename(opts.sbom)}.${other.length ? ` Not checked (other package types): ${other.join(", ")}.` : ""}`));
      }
    }

    if (opts.markdown) await writeFile(opts.markdown, toMarkdown(all), "utf8");
    if (opts.vex) {
      const statements = vexStatements(vexSources, opts.vexProduct);
      await writeFile(opts.vex, JSON.stringify(openVex(statements), null, 2) + "\n", "utf8");
      console.error(pc.dim(`Wrote ${statements.length} VEX statements to ${opts.vex}.`));
    }
    if (opts.sarif) await writeFile(opts.sarif, JSON.stringify(mergeSarif(logs), null, 2) + "\n", "utf8");
    // One project keeps the original output shape: a plain array of findings.
    if (opts.json) console.log(JSON.stringify(all.length === 1 ? all[0].findings : all, null, 2));
    const everything = all.flatMap((p) => p.findings);
    if (opts.updateBaseline && !opts.baseline) throw new Error("--update-baseline needs --baseline <file>.");
    if (opts.baseline && opts.updateBaseline) {
      const count = await writeBaseline(opts.baseline, everything);
      console.error(pc.dim(`Baseline written to ${opts.baseline} (${count} known vulnerabilities).`));
      process.exitCode = 0;
      return;
    }
    let gate = everything;
    if (opts.baseline) {
      // Known vulnerabilities stay visible in the report but only new ones can fail the build.
      const { fresh, known } = splitByBaseline(everything, await readBaseline(opts.baseline));
      console.error(pc.dim(`Baseline: ${known} known, ${fresh.reduce((n, f) => n + f.vulns.length, 0)} new.`));
      gate = fresh;
    }
    process.exitCode = gate.some((f) => fails(f, opts.failOn, opts.epssThreshold)) ? 1 : 0;
  });

program
  .command("fix")
  .description("Upgrade vulnerable packages and let the model repair code that breaks, verified by your checks")
  .argument("[dir]", "project directory containing package-lock.json", ".")
  .option("--check <cmd...>", "verification commands (default: typecheck/build/test scripts)")
  .option("--only <pkg...>", "only fix these packages")
  .option("--lockfile <file>", "which lockfile to fix when the directory has several (e.g. uv.lock next to package-lock.json)")
  .option("--max-attempts <n>", "model repair rounds per package", (v) => Number.parseInt(v, 10), 3)
  .option("--max-cost <usd>", "stop calling the model once this much has been spent; the fix in progress rolls back", (v) => Number.parseFloat(v))
  .option("--no-dev", "ignore dev-only dependencies")
  .option("--no-breaking", "only apply semver-compatible upgrades")
  .option("--no-backport", "never port upstream fixes into installed packages")
  .option("--prefer-backport", "backport instead of making a breaking upgrade")
  .option("--ignore-scripts", "do not run packages' install scripts (also turns backports off, which need the project's postinstall)")
  .option("--allow-changes <path...>", "files or directories a fix may change besides its own (e.g. committed build output)")
  .option("--audit-log <file>", "where to write the run's audit log (default .autofix-cve/audit/fix-<time>.jsonl)")
  .option("--no-audit", "do not write an audit log")
  .option("--no-memory", "neither use nor record lessons from earlier runs (.autofix-cve/memory.json)")
  .option("--dry-run", "show the plan and exit without changing anything")
  .option("-y, --yes", "apply the plan without asking (for CI)")
  .option("--allow-dirty", "run even if the git working tree has uncommitted changes")
  .option("--pr", "commit the fixes on a new branch, push it and open a GitHub pull request")
  .option("--json", "print machine-readable JSON")
  .action(
    async (
      dir: string,
      opts: {
        check?: string[];
        only?: string[];
        lockfile?: string;
        maxAttempts: number;
        maxCost?: number;
        dev: boolean;
        breaking: boolean;
        backport: boolean;
        preferBackport?: boolean;
        ignoreScripts?: boolean;
        allowChanges?: string[];
        audit?: boolean;
        auditLog?: string;
        memory?: boolean;
        dryRun?: boolean;
        yes?: boolean;
        allowDirty?: boolean;
        pr?: boolean;
        json?: boolean;
      },
    ) => {
      const projectDir = path.resolve(dir);
      const log = (m: string) => console.error(pc.dim(m));
      if (opts.ignoreScripts) {
        process.env.AUTOFIX_IGNORE_SCRIPTS = "1";
        opts.backport = false;
      }

      const found = detectLockfiles(projectDir);
      const lock = opts.lockfile ? found.find((l) => l.file === opts.lockfile) : found[0];
      if (!lock) {
        throw new Error(
          opts.lockfile
            ? `${opts.lockfile} is not one of the lockfiles found here: ${found.map((l) => l.file).join(", ") || "none"}.`
            : `No lockfile in ${projectDir}.`,
        );
      }
      if (!opts.lockfile && found.length > 1) {
        log(`Several lockfiles here (${found.map((l) => l.file).join(", ")}); fixing ${lock.file}. Use --lockfile to pick another.`);
      }
      if (!FIXABLE.includes(lock.kind)) {
        throw new Error(`fix needs a lockfile it can regenerate; ${lock.file} can be scanned but not fixed.`);
      }
      const manager = managerFor(lock.kind, projectDir);

      if (!opts.allowDirty && (await uncommittedChanges(projectDir))) {
        throw new Error("Uncommitted changes in the git working tree. Commit or stash them, or pass --allow-dirty.");
      }

      log("Scanning dependencies…");
      const findings = (await scan(projectDir, { includeDev: opts.dev, lock })).filter(
        (f) => !opts.only || opts.only.includes(f.dependency.name),
      );
      if (findings.length === 0) {
        console.log(opts.json ? JSON.stringify({ plan: [], results: [], remaining: [] }, null, 2) : pc.green("Nothing to fix."));
        return;
      }

      const checks = opts.check ?? (await detectChecks(projectDir, lock.kind));
      const policy = {
        checks,
        allowBreaking: opts.breaking,
        backport: opts.backport,
        preferBackport: !!opts.preferBackport,
        canOverride: manager.canOverride,
      };
      // One step per installed name@version: each copy of a package is fixed on its own.
      const plan = findings.map((f) => planFinding(f, policy));

      (opts.json ? console.error : console.log)(formatPlan(plan, checks));
      const base = opts.pr ? await checkPrPrerequisites(projectDir) : undefined;
      if (base) console.error(pc.dim(`  Fixes will be committed to a new branch and opened as a PR against ${base}.`));
      const actionable = plan.filter((s) => s.action !== "skip");
      if (opts.dryRun || actionable.length === 0) {
        // JSON consumers always get a document, even when nothing will run.
        if (opts.json) {
          const summary = plan.map((s) => ({ package: s.finding.dependency.name, version: s.finding.dependency.version, action: s.action, reason: s.reason }));
          console.log(JSON.stringify({ plan: summary, results: [], remaining: findings }, null, 2));
        }
        return;
      }
      if (!opts.yes) {
        if (!process.stdin.isTTY) throw new Error("Not running in a terminal; pass --yes to apply the plan.");
        if (!(await confirm(`Apply ${actionable.length} change(s)? [y/N] `))) {
          console.log("Aborted; nothing was changed.");
          return;
        }
      }
      const auditFile = openAudit(projectDir, "fix", opts, {
        lockfile: lock.file,
        checks,
        plan: plan.map((s) => ({ package: s.finding.dependency.name, version: s.finding.dependency.version, action: s.action, reason: s.reason })),
      });
      if (checks.length) await verifyBaseline(projectDir, checks);
      const branch = base ? await createBranch(projectDir) : undefined;

      const memory = opts.memory === false ? undefined : FileMemory.forProject(projectDir);
      const fixOpts = {
        ...policy,
        manager,
        maxAttempts: opts.maxAttempts,
        backend: withBudget(createBackend(), opts.maxCost),
        osv: new OsvClient(),
        log,
        memory,
      };
      log(`Model: ${DEFAULT_MODEL}`);
      const results: FixResult[] = [];
      const runStep = async (step: (typeof plan)[number]): Promise<FixResult> => {
        const { finding } = step;
        if (step.action === "backport") return backportFinding(projectDir, finding, fixOpts);
        const result = await fixFinding(projectDir, finding, fixOpts);
        if (result.status === "failed" && policy.backport && canBackport(finding)) {
          log("  upgrade failed; falling back to a backport");
          const fallback = await backportFinding(projectDir, finding, fixOpts);
          const upgradeNote = `upgrade to ${result.to} failed (${result.reason})`;
          return { ...fallback, reason: [upgradeNote, fallback.reason].filter(Boolean).join("; "), costUsd: fallback.costUsd + result.costUsd };
        }
        return result;
      };
      for (const step of plan) {
        log(`\n${step.finding.dependency.name}@${step.finding.dependency.version}`);
        const snap = await scopeSnapshot(projectDir);
        const result = await runStep(step);
        const final = await enforceScope(projectDir, snap, result, "fixed", manager.manifestFiles, opts.allowChanges ?? [], () => manager.install());
        results.push(final);
        const lesson = lessonFrom(step.finding.dependency, final);
        if (memory && lesson) await memory.record(lesson);
      }

      log("\nRescanning…");
      const remaining = await scan(projectDir, { includeDev: opts.dev });
      auditEvent("results", { results, remaining: remaining.map((f) => `${f.dependency.name}@${f.dependency.version}`) });
      if (auditFile) log(`Audit log: ${path.relative(process.cwd(), auditFile)}`);
      if (opts.json) console.log(JSON.stringify({ results, remaining }, null, 2));
      else console.log(formatFixSummary(results, remaining));

      if (base && branch) {
        if (results.some((r) => r.status === "fixed")) {
          const url = await openPr(projectDir, base, branch, results, remaining);
          console.log(pc.green(`Pull request: ${url}`));
        } else {
          await abandonBranch(projectDir, base, branch);
          log(`Nothing was fixed; deleted branch ${branch}.`);
        }
      } else if (!opts.json && results.some((r) => r.status === "fixed")) {
        console.log(pc.dim("Changes are left in the working tree for review."));
      }
      process.exitCode = results.some((r) => r.status !== "fixed") ? 1 : 0;
    },
  );

program
  .command("mitigate")
  .description("For vulnerabilities with no fixed release: add guards at your own call sites, verified by your checks")
  .argument("[dir]", "project directory", ".")
  .option("--check <cmd...>", "verification commands (default: typecheck/build/test scripts)")
  .option("--only <pkg...>", "only these packages")
  .option("--lockfile <file>", "which lockfile to use when the directory has several")
  .option("--max-attempts <n>", "model rounds per package when checks fail", (v) => Number.parseInt(v, 10), 2)
  .option("--max-cost <usd>", "stop calling the model once this much has been spent", (v) => Number.parseFloat(v))
  .option("--dry-run", "list what would be mitigated and exit")
  .option("-y, --yes", "go ahead without asking (for CI)")
  .option("--allow-dirty", "run even if the git working tree has uncommitted changes")
  .option("--ignore-scripts", "do not run packages' install scripts")
  .option("--allow-changes <path...>", "files or directories a mitigation may change besides the ones it edits")
  .option("--audit-log <file>", "where to write the run's audit log (default .autofix-cve/audit/mitigate-<time>.jsonl)")
  .option("--no-audit", "do not write an audit log")
  .option("--no-memory", "neither use nor record lessons from earlier runs (.autofix-cve/memory.json)")
  .option("--json", "print machine-readable JSON")
  .action(
    async (
      dir: string,
      opts: {
        check?: string[];
        only?: string[];
        lockfile?: string;
        maxAttempts: number;
        maxCost?: number;
        ignoreScripts?: boolean;
        allowChanges?: string[];
        audit?: boolean;
        auditLog?: string;
        memory?: boolean;
        dryRun?: boolean;
        yes?: boolean;
        allowDirty?: boolean;
        json?: boolean;
      },
    ) => {
      const projectDir = path.resolve(dir);
      const log = (m: string) => console.error(pc.dim(m));
      if (opts.ignoreScripts) process.env.AUTOFIX_IGNORE_SCRIPTS = "1";
      const found = detectLockfiles(projectDir);
      const lock = opts.lockfile ? found.find((l) => l.file === opts.lockfile) : found[0];
      if (!lock) throw new Error(opts.lockfile ? `${opts.lockfile} is not a lockfile found here.` : `No lockfile in ${projectDir}.`);
      if (!opts.allowDirty && (await uncommittedChanges(projectDir))) {
        throw new Error("Uncommitted changes in the git working tree. Commit or stash them, or pass --allow-dirty.");
      }

      log("Scanning dependencies…");
      const findings = (await scan(projectDir, { includeDev: false, lock })).filter(
        (f) => (!opts.only || opts.only.includes(f.dependency.name)) && !f.mitigation,
      );
      const candidates = mitigationCandidates(findings);
      const out = opts.json ? console.error : console.log;
      if (candidates.length === 0) {
        if (opts.json) console.log(JSON.stringify({ results: [] }, null, 2));
        else console.log(pc.green("Nothing to mitigate: every vulnerability your code calls into has a fixed release (use `fix`)."));
        return;
      }
      const checks = opts.check ?? (await detectChecks(projectDir, lock.kind));
      out(pc.bold("Mitigation plan"));
      for (const f of candidates) {
        const sites = callSites(f);
        out(`  ${pc.bold(`${f.dependency.name}@${f.dependency.version}`)}  ${pc.dim(`${unfixedVulns(f).length} without a fixed release, ${sites.length} call site(s) in ${[...new Set(sites.map((u) => u.file))].join(", ")}`)}`);
      }
      out(pc.dim(`  verify with: ${checks.length ? checks.join(" → ") : "(none found; pass --check)"}`));
      out(pc.dim("  Only your own files are edited; failed attempts are rolled back. The vulnerabilities stay reported, marked as mitigated."));
      if (opts.dryRun) return;
      if (!opts.yes) {
        if (!process.stdin.isTTY) throw new Error("Not running in a terminal; pass --yes to go ahead.");
        if (!(await confirm(`Mitigate ${candidates.length} package(s)? [y/N] `))) {
          console.log("Aborted; nothing was changed.");
          return;
        }
      }
      const auditFile = openAudit(projectDir, "mitigate", opts, {
        lockfile: lock.file,
        checks,
        candidates: candidates.map((f) => `${f.dependency.name}@${f.dependency.version}`),
      });
      if (checks.length) await verifyBaseline(projectDir, checks);

      const backend = withBudget(createBackend(), opts.maxCost);
      const memory = opts.memory === false ? undefined : FileMemory.forProject(projectDir);
      const results: MitigateResult[] = [];
      for (const f of candidates) {
        log(`\n${f.dependency.name}@${f.dependency.version}`);
        const snap = await scopeSnapshot(projectDir);
        const result = await mitigateFinding(projectDir, f, { backend, checks, maxAttempts: opts.maxAttempts, log, memory });
        const final = await enforceScope(projectDir, snap, result, "mitigated", [], opts.allowChanges ?? []);
        results.push(final);
        const lesson = lessonFrom(f.dependency, final, "mitigate");
        if (memory && lesson) await memory.record(lesson);
      }
      auditEvent("results", { results });
      if (auditFile) log(`Audit log: ${path.relative(process.cwd(), auditFile)}`);
      if (opts.json) {
        console.log(JSON.stringify({ results }, null, 2));
        return;
      }
      console.log(pc.bold("\nMitigation summary"));
      const label = { mitigated: pc.green("MITIGATED"), "not-applicable": pc.yellow("NOT APPLICABLE"), failed: pc.red("FAILED") };
      for (const r of results) {
        console.log(`${label[r.status]}  ${pc.bold(`${r.package}@${r.version}`)}  ${pc.dim(r.vulns.join(", "))}`);
        if (r.explanation) console.log(`  ${pc.cyan("guards:")} ${r.explanation}`);
        if (r.residualRisk) console.log(`  ${pc.yellow("still exploitable:")} ${r.residualRisk}`);
        if (r.reason && r.status !== "not-applicable") console.log(`  ${pc.dim(r.reason)}`);
        if (r.changedFiles.length) console.log(`  ${pc.dim(`changed: ${r.changedFiles.join(", ")}`)}`);
        if (r.costUsd) console.log(`  ${pc.dim(`model rounds: ${r.attempts}, cost: $${r.costUsd.toFixed(4)}`)}`);
      }
      if (results.some((r) => r.status === "mitigated")) {
        console.log(pc.dim("Changes are left in the working tree for review. Upgrade with `fix` as soon as a fixed release ships."));
      }
    },
  );

program
  .command("vet")
  .description("Check packages before adding them: malware, known vulnerabilities, deprecation, release age and license")
  .argument("<packages...>", "e.g. lodash@4.17.21, pypi:requests==2.31.0, go:github.com/gin-gonic/gin@v1.9.0, cargo:serde, nuget:Newtonsoft.Json@13.0.1")
  .option("--min-age <days>", "flag releases younger than this", (v) => Number.parseInt(v, 10), 7)
  .option("--allow-license <spdx...>", "only these licenses pass (an unknown license then fails)")
  .option("--deny-license <spdx...>", "these licenses fail")
  .addOption(
    new Option("--min-severity <level>", "vulnerabilities rated below this only warn").choices(["low", "moderate", "high", "critical"]),
  )
  .option("--strict", "treat warnings (young release, unknown license, minor vulnerabilities) as failures")
  .option("--json", "print machine-readable JSON")
  .action(
    async (
      specs: string[],
      opts: { minAge: number; allowLicense?: string[]; denyLicense?: string[]; minSeverity?: Severity; strict?: boolean; json?: boolean },
    ) => {
      const policy: VetPolicy = {
        minAgeDays: opts.minAge,
        allowLicenses: opts.allowLicense,
        denyLicenses: opts.denyLicense,
        minSeverity: opts.minSeverity,
        strict: opts.strict,
      };
      const osv = new OsvClient();
      const results = await mapLimit(specs.map(parseSpec), 4, (spec) => vetPackage(spec, policy, { osv }));
      if (opts.json) console.log(JSON.stringify(results, null, 2));
      else console.log(formatVet(results));
      process.exitCode = results.some((r) => r.verdict === "fail") ? 1 : 0;
    },
  );

program
  .command("audit")
  .description("Everything at once: lockfiles (recursively), runtimes in Dockerfiles and SBOMs, with vulnerabilities that span several components grouped")
  .argument("[dir]", "repository root", ".")
  .option("--sbom <files...>", "also scan these CycloneDX or SPDX SBOMs (e.g. of deployed images)")
  .option("--no-dev", "ignore dev-only dependencies")
  .option("--json", "print machine-readable JSON")
  .addOption(
    new Option("--fail-on <level>", "exit 1 when anything matches: any, high, risk (known exploited, or high and reachable), none")
      .choices(["any", "high", "risk", "none"])
      .default("none"),
  )
  .option("--epss-threshold <p>", "with --fail-on risk: also fail on vulnerabilities whose EPSS score is at least this (0-1, e.g. 0.1)", parseProbability)
  .action(async (dir: string, opts: { sbom?: string[]; dev: boolean; json?: boolean; failOn: FailOn; epssThreshold?: number }) => {
    const root = path.resolve(dir);
    const rel = (p: string) => path.relative(root, p).split(path.sep).join("/") || ".";
    const log = (m: string) => console.error(pc.dim(m));
    const exposures: Exposure[] = [];
    const packages: { source: string; findings: Finding[] }[] = [];

    for (const { dir: projectDir, lock } of await discoverProjects(root)) {
      const source = rel(path.join(projectDir, lock.file));
      log(`Scanning ${source}…`);
      packages.push({ source, findings: await scan(projectDir, { includeDev: opts.dev, lock }) });
    }
    for (const file of opts.sbom ?? []) {
      log(`Scanning ${file}…`);
      const { deps } = await readSbom(file);
      packages.push({ source: path.basename(file), findings: await scanDependencies(deps, root, { includeDev: true }) });
    }
    for (const { source, findings } of packages) {
      for (const f of findings) {
        const d = f.dependency;
        const bins = d.binaries ? ` (${d.binaries.map((b) => b.name).join(", ")})` : "";
        exposures.push({ where: source, component: `${d.name} ${d.version}${bins}`, fix: f.safeVersion && `${d.name} ${f.safeVersion}`, vulns: f.vulns, unfixable: f.unfixable });
      }
    }
    log("Checking runtimes in Dockerfiles…");
    const runtimes = await scanRuntimes(root);
    for (const r of runtimes) {
      const s = r.status;
      exposures.push({
        where: `${r.file}:${r.line}${r.shipped ? "" : " (build stage)"}`,
        component: `${s.runtime} ${s.version ?? `${s.line}.x (floating)`}`,
        fix: r.edit?.to.trim() ?? (s.latest ? `${s.runtime} ${s.latest}` : undefined),
        vulns: s.vulns,
      });
    }
    const groups = correlate(exposures);

    if (opts.json) {
      console.log(JSON.stringify({ upstream: groups, packages, runtimes }, null, 2));
    } else {
      const count = (fs: Finding[]) => fs.reduce((n, f) => n + f.vulns.length, 0);
      console.log(formatUpstreamGroups(groups));
      console.log(pc.bold("Summary"));
      for (const p of packages) {
        console.log(`  ${p.source.padEnd(40)} ${p.findings.length ? `${count(p.findings)} vulnerabilities in ${p.findings.length} packages (${severityBreakdown(p.findings)})` : pc.green("clean")}`);
      }
      for (const r of runtimes) {
        const s = r.status;
        const state = s.vulns.length ? `${s.vulns.length} fixed in newer releases` : s.version ? pc.green("up to date") : pc.yellow("floating tag");
        console.log(`  ${`${r.file}:${r.line}`.padEnd(40)} ${s.runtime} ${s.version ?? `${s.line}.x`}: ${state}${r.eolDays !== undefined && r.eolDays <= 90 ? pc.red(`, support ends ${s.eol}`) : ""}`);
      }
      console.log(pc.dim("\nDetails: `scan -r`, `scan --sbom` and `runtime` show each source in full; `fix` and `runtime --fix` apply the fixes."));
    }
    const failing =
      packages.some((p) => p.findings.some((f) => fails(f, opts.failOn, opts.epssThreshold))) ||
      runtimes.some((r) => runtimeFails(r, opts.failOn, opts.epssThreshold));
    process.exitCode = failing ? 1 : 0;
  });

program
  .command("runtime")
  .description("Check the Node.js and .NET runtimes your Dockerfiles build on, which dependency scans do not see")
  .argument("[dir]", "directory to search for Dockerfiles (subdirectories included)", ".")
  .option("--json", "print machine-readable JSON")
  .option("--fix", "pin each affected or floating base image to the newest release of its line")
  .addOption(
    new Option("--fail-on <level>", "exit 1 when a shipped image has: any (vulnerability or end of life), high/risk (known exploited, high or unrated), none")
      .choices(["any", "high", "risk", "none"])
      .default("any"),
  )
  .option("--epss-threshold <p>", "with --fail-on risk: also fail on vulnerabilities whose EPSS score is at least this (0-1, e.g. 0.1)", parseProbability)
  .action(async (dir: string, opts: { json?: boolean; fix?: boolean; failOn: FailOn; epssThreshold?: number }) => {
    const root = path.resolve(dir);
    const findings = await scanRuntimes(root);
    if (opts.json) console.log(JSON.stringify(findings, null, 2));
    else console.log(formatRuntimeReport(findings));
    if (opts.fix) {
      const changed = await applyRuntimeEdits(root, findings);
      (opts.json ? console.error : console.log)(
        changed.length ? pc.green(`Pinned base images in ${changed.join(", ")}. Rebuild the images to pick up the fixes.`) : pc.dim("Nothing to pin."),
      );
    }
    // After --fix the edits still need a rebuild, so the exit code reflects what is deployed now.
    process.exitCode = findings.some((f) => runtimeFails(f, opts.failOn, opts.epssThreshold)) ? 1 : 0;
  });

program
  .command("verify")
  .description("Re-run the stored PoCs for every backport; fails if any vulnerability is back (use in CI)")
  .argument("[dir]", "project directory", ".")
  .action(async (dir: string) => {
    const projectDir = path.resolve(dir);
    const { backports } = await readManifest(projectDir);
    if (backports.length === 0) {
      console.log(`No backports recorded in ${MANIFEST}.`);
      return;
    }
    let bad = 0;
    for (const b of backports) {
      const installed = await readInstalledVersion(projectDir, b.package);
      if (installed !== b.version) {
        console.log(`${pc.yellow("STALE")}  ${b.package}: patch is for ${b.version}, installed ${installed ?? "nothing"}`);
        continue;
      }
      for (const poc of b.pocs) {
        const res = await runPoc(projectDir, path.join(projectDir, poc));
        const label = res.verdict === "safe" ? pc.green("SAFE") : pc.red(res.verdict.toUpperCase());
        console.log(`${label}  ${b.package}@${b.version}  ${poc}`);
        if (res.verdict !== "safe") {
          bad++;
          console.log(pc.dim(res.output));
        }
      }
    }
    process.exitCode = bad ? 1 : 0;
  });

program
  .command("doctor")
  .description("Check which external tools are available and what they enable")
  .action(async () => {
    const osv = await fetch(`${endpoints.osv()}/vulns/GHSA-35jh-r3h4-6jhm`).then((r) => r.ok).catch(() => false);
    console.log(`${osv ? pc.green("ok     ") : pc.red("missing")}  ${"OSV API".padEnd(8)}  ${pc.dim("scan (required)")}`);
    for (const t of await checkTools()) {
      const status = t.ok ? pc.green("ok     ") : pc.yellow("missing");
      const hint = !t.ok && t.env ? pc.dim(` (set ${t.env} to use another command)`) : "";
      console.log(`${status}  ${t.name.padEnd(8)}  ${pc.dim(t.ok ? `${t.detail} → ${t.enables}` : t.enables)}${hint}`);
    }
    process.exitCode = osv ? 0 : 1;
  });

program.parseAsync().catch((err: unknown) => {
  console.error(pc.red(err instanceof Error ? err.message : String(err)));
  process.exitCode = 2;
});
