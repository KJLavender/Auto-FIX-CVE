#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { createInterface } from "node:readline/promises";
import { Command, Option } from "commander";
import pc from "picocolors";
import { backportFinding, canBackport } from "./backport/backport.js";
import { appliedBackports, MANIFEST, readManifest } from "./backport/manifest.js";
import { runPoc } from "./backport/poc.js";
import { detectChecks } from "./fix/context.js";
import { run } from "./fix/exec.js";
import { FIXABLE, managerFor } from "./fix/managers.js";
import { fixFinding, planFinding, readInstalledVersion, verifyBaseline, type FixResult } from "./fix/upgrade.js";
import { CliBackend, DEFAULT_MODEL } from "./llm/backend.js";
import { detectLockfile, detectLockfiles, discoverProjects } from "./lockfile/index.js";
import { OsvClient } from "./osv/client.js";
import { abandonBranch, checkPrPrerequisites, createBranch, openPr } from "./pr.js";
import { formatFixSummary, formatPlan, formatReport } from "./report.js";
import { toMarkdown } from "./markdown.js";
import { mergeSarif, toSarif, type SarifLog } from "./sarif.js";
import { triageFindings } from "./triage.js";
import { fails, scan, type FailOn } from "./scan.js";
import type { Finding } from "./types.js";

const VERSION = "0.1.0";


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
  failOn: FailOn;
  triage?: boolean;
  triageLimit: number;
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
    new Option("--fail-on <level>", "exit 1 when findings match: any, likely (reachable), high (severity), none")
      .choices(["any", "likely", "high", "none"])
      .default("any"),
  )
  .option("--triage", "ask the model whether each imported vulnerable package is reachable from your call sites")
  .option("--triage-limit <n>", "packages to triage at most, per project", (v) => Number.parseInt(v, 10), 10)
  .action(async (dir: string, opts: ScanCliOptions) => {
    const root = path.resolve(dir);
    const projects = opts.recursive
      ? await discoverProjects(root)
      : detectLockfiles(root).map((lock) => ({ dir: root, lock }));
    if (projects.length === 0) throw new Error(`No lockfile found in ${root}${opts.recursive ? " or below" : ""}.`);

    const log = (m: string) => console.error(pc.dim(m));
    const all: { project: string; lockfile: string; findings: Finding[] }[] = [];
    const logs: SarifLog[] = [];
    for (const { dir: projectDir, lock } of projects) {
      const label = path.relative(root, path.join(projectDir, lock.file)).split(path.sep).join("/");
      const findings = await scan(projectDir, { includeDev: opts.dev, lock });
      if (opts.triage) {
        const cost = await triageFindings(projectDir, findings, new CliBackend(), opts.triageLimit, log);
        log(`Triage cost (${label}): $${cost.toFixed(4)}`);
      }
      if (opts.sarif) logs.push(await toSarif(projectDir, findings, VERSION, process.cwd(), lock));
      all.push({ project: path.relative(root, projectDir).split(path.sep).join("/") || ".", lockfile: label, findings });

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
    }

    if (opts.markdown) await writeFile(opts.markdown, toMarkdown(all), "utf8");
    if (opts.sarif) await writeFile(opts.sarif, JSON.stringify(mergeSarif(logs), null, 2) + "\n", "utf8");
    // One project keeps the original output shape: a plain array of findings.
    if (opts.json) console.log(JSON.stringify(all.length === 1 ? all[0].findings : all, null, 2));
    process.exitCode = all.some((p) => p.findings.some((f) => fails(f, opts.failOn))) ? 1 : 0;
  });

program
  .command("fix")
  .description("Upgrade vulnerable packages and let the model repair code that breaks, verified by your checks")
  .argument("[dir]", "project directory containing package-lock.json", ".")
  .option("--check <cmd...>", "verification commands (default: typecheck/build/test scripts)")
  .option("--only <pkg...>", "only fix these packages")
  .option("--max-attempts <n>", "model repair rounds per package", (v) => Number.parseInt(v, 10), 3)
  .option("--no-dev", "ignore dev-only dependencies")
  .option("--no-breaking", "only apply semver-compatible upgrades")
  .option("--no-backport", "never port upstream fixes into installed packages")
  .option("--prefer-backport", "backport instead of making a breaking upgrade")
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
        maxAttempts: number;
        dev: boolean;
        breaking: boolean;
        backport: boolean;
        preferBackport?: boolean;
        dryRun?: boolean;
        yes?: boolean;
        allowDirty?: boolean;
        pr?: boolean;
        json?: boolean;
      },
    ) => {
      const projectDir = path.resolve(dir);
      const log = (m: string) => console.error(pc.dim(m));

      const lock = detectLockfile(projectDir);
      if (!FIXABLE.includes(lock.kind)) {
        throw new Error(`fix needs a lockfile it can regenerate (npm, pnpm, Yarn, uv, Poetry or Pipenv); ${lock.file} can be scanned but not fixed.`);
      }
      const manager = managerFor(lock.kind, projectDir);

      const status = await run("git status --porcelain", projectDir);
      if (status.ok && status.output.trim() && !opts.allowDirty) {
        throw new Error("Uncommitted changes in the git working tree. Commit or stash them, or pass --allow-dirty.");
      }

      log("Scanning dependencies…");
      const findings = (await scan(projectDir, { includeDev: opts.dev })).filter(
        (f) => !opts.only || opts.only.includes(f.dependency.name),
      );
      if (findings.length === 0) {
        console.log(pc.green("Nothing to fix."));
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
      if (opts.dryRun || actionable.length === 0) return;
      if (!opts.yes) {
        if (!process.stdin.isTTY) throw new Error("Not running in a terminal; pass --yes to apply the plan.");
        if (!(await confirm(`Apply ${actionable.length} change(s)? [y/N] `))) {
          console.log("Aborted; nothing was changed.");
          return;
        }
      }
      if (checks.length) await verifyBaseline(projectDir, checks);
      const branch = base ? await createBranch(projectDir) : undefined;

      const fixOpts = {
        ...policy,
        manager,
        maxAttempts: opts.maxAttempts,
        backend: new CliBackend(),
        osv: new OsvClient(),
        log,
      };
      log(`Model: ${DEFAULT_MODEL}`);
      const results: FixResult[] = [];
      for (const step of plan) {
        const { finding } = step;
        log(`\n${finding.dependency.name}@${finding.dependency.version}`);
        if (step.action === "backport") {
          results.push(await backportFinding(projectDir, finding, fixOpts));
          continue;
        }
        const result = await fixFinding(projectDir, finding, fixOpts);
        results.push(result);
        if (result.status === "failed" && policy.backport && canBackport(finding)) {
          log("  upgrade failed; falling back to a backport");
          const fallback = await backportFinding(projectDir, finding, fixOpts);
          const upgradeNote = `upgrade to ${result.to} failed (${result.reason})`;
          results[results.length - 1] = {
            ...fallback,
            reason: [upgradeNote, fallback.reason].filter(Boolean).join("; "),
            costUsd: fallback.costUsd + result.costUsd,
          };
        }
      }

      log("\nRescanning…");
      const remaining = await scan(projectDir, { includeDev: opts.dev });
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

program.parseAsync().catch((err: unknown) => {
  console.error(pc.red(err instanceof Error ? err.message : String(err)));
  process.exitCode = 2;
});
