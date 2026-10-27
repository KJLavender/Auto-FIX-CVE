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
import { BudgetBackend, createBackend, DEFAULT_MODEL, type LlmBackend } from "./llm/backend.js";
import { detectLockfiles, discoverProjects } from "./lockfile/index.js";
import { OsvClient } from "./osv/client.js";
import { abandonBranch, checkPrPrerequisites, createBranch, openPr } from "./pr.js";
import { formatFixSummary, formatPlan, formatReport } from "./report.js";
import { toMarkdown } from "./markdown.js";
import { mergeSarif, toSarif, type SarifLog } from "./sarif.js";
import { triageFindings } from "./triage.js";
import { debianDownloadList, readSbom } from "./sbom.js";
import { fails, scan, scanDependencies, type FailOn, type IgnoredVuln, type Severity } from "./scan.js";
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
  triage?: boolean;
  triageLimit: number;
  maxCost?: number;
  sbom?: string;
  debList?: string;
}

/** Caps model spend when a limit is given; useful on a subscription or a large repo. */
function withBudget(backend: LlmBackend, maxCost: number | undefined): LlmBackend {
  return maxCost === undefined ? backend : new BudgetBackend(backend, maxCost);
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
  .option("--triage", "ask the model whether each imported vulnerable package is reachable from your call sites")
  .option("--triage-limit <n>", "packages to triage at most, per project", (v) => Number.parseInt(v, 10), 10)
  .option("--max-cost <usd>", "stop triaging once this much has been spent on the model", (v) => Number.parseFloat(v))
  .option("--sbom <file>", "scan a CycloneDX or SPDX JSON SBOM (e.g. of a deployed image) instead of lockfiles")
  .option("--deb-list <file>", "with --sbom: write `package=version` lines for the fixed Debian packages, for offline download")
  .action(async (dir: string, opts: ScanCliOptions) => {
    const root = path.resolve(dir);
    if (opts.debList && !opts.sbom) throw new Error("--deb-list needs --sbom.");
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
      if (opts.debList) {
        const lines = debianDownloadList(findings);
        await writeFile(opts.debList, lines.map((l) => `${l}\n`).join(""), "utf8");
        console.error(pc.dim(`Wrote ${lines.length} Debian package pins to ${opts.debList}.`));
      }
      if (!opts.json) {
        console.log(formatReport(findings, opts.maxUsages, false));
        for (const i of ignored) console.log(`${pc.dim("ignored")}  ${i.package}@${i.version} ${i.id}  ${pc.dim(i.reason)}`);
        const other = Object.entries(skipped).map(([type, n]) => `${type} ${n}`);
        console.log(pc.dim(`Checked ${deps.length} packages from ${path.basename(opts.sbom)}.${other.length ? ` Not checked (other package types): ${other.join(", ")}.` : ""}`));
      }
    }

    if (opts.markdown) await writeFile(opts.markdown, toMarkdown(all), "utf8");
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
    process.exitCode = gate.some((f) => fails(f, opts.failOn)) ? 1 : 0;
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
        dryRun?: boolean;
        yes?: boolean;
        allowDirty?: boolean;
        pr?: boolean;
        json?: boolean;
      },
    ) => {
      const projectDir = path.resolve(dir);
      const log = (m: string) => console.error(pc.dim(m));

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

      const status = await run("git status --porcelain", projectDir);
      if (status.ok && status.output.trim() && !opts.allowDirty) {
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
      if (checks.length) await verifyBaseline(projectDir, checks);
      const branch = base ? await createBranch(projectDir) : undefined;

      const fixOpts = {
        ...policy,
        manager,
        maxAttempts: opts.maxAttempts,
        backend: withBudget(createBackend(), opts.maxCost),
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
  .action(async (dir: string, opts: { json?: boolean; fix?: boolean; failOn: FailOn }) => {
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
    process.exitCode = findings.some((f) => runtimeFails(f, opts.failOn)) ? 1 : 0;
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
