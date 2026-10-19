#!/usr/bin/env node
import path from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { detectChecks } from "./fix/context.js";
import { run } from "./fix/exec.js";
import { fixFinding, verifyBaseline, type FixResult } from "./fix/upgrade.js";
import { ClaudeCliBackend, DEFAULT_MODEL } from "./llm/backend.js";
import { OsvClient } from "./osv/client.js";
import { formatReport, formatFixSummary } from "./report.js";
import { scan } from "./scan.js";

const program = new Command();

program
  .name("autofix-cve")
  .description("Find CVEs in your dependencies, locate where your code uses them, and fix them.")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a project's lockfile for known vulnerabilities and map them to your code")
  .argument("[dir]", "project directory containing package-lock.json", ".")
  .option("--json", "print machine-readable JSON")
  .option("--no-dev", "ignore dev-only dependencies")
  .option("--max-usages <n>", "usages to show per package", (v) => Number.parseInt(v, 10), 10)
  .action(async (dir: string, opts: { json?: boolean; dev: boolean; maxUsages: number }) => {
    const findings = await scan(path.resolve(dir), { includeDev: opts.dev });
    console.log(opts.json ? JSON.stringify(findings, null, 2) : formatReport(findings, opts.maxUsages));
    process.exitCode = findings.length ? 1 : 0;
  });

program
  .command("fix")
  .description("Upgrade vulnerable packages and let the model repair code that breaks, verified by your checks")
  .argument("[dir]", "project directory containing package-lock.json", ".")
  .option("--check <cmd...>", "verification commands (default: typecheck/build/test scripts)")
  .option("--only <pkg...>", "only fix these packages")
  .option("--max-attempts <n>", "model repair rounds per package", (v) => Number.parseInt(v, 10), 3)
  .option("--no-dev", "ignore dev-only dependencies")
  .option("--allow-dirty", "run even if the git working tree has uncommitted changes")
  .option("--json", "print machine-readable JSON")
  .action(
    async (
      dir: string,
      opts: { check?: string[]; only?: string[]; maxAttempts: number; dev: boolean; allowDirty?: boolean; json?: boolean },
    ) => {
      const projectDir = path.resolve(dir);
      const log = (m: string) => console.error(pc.dim(m));

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

      const checks = opts.check ?? (await detectChecks(projectDir));
      log(checks.length ? `Verification: ${checks.join(" → ")}` : "No verification commands found.");
      if (checks.length) await verifyBaseline(projectDir, checks);

      const fixOpts = {
        checks,
        maxAttempts: opts.maxAttempts,
        backend: new ClaudeCliBackend(),
        osv: new OsvClient(),
        log,
      };
      log(`Model: ${DEFAULT_MODEL}`);
      const results: FixResult[] = [];
      const seen = new Set<string>();
      for (const finding of findings) {
        if (seen.has(finding.dependency.name)) continue;
        seen.add(finding.dependency.name);
        log(`\n${finding.dependency.name}@${finding.dependency.version}`);
        results.push(await fixFinding(projectDir, finding, fixOpts));
      }

      log("\nRescanning…");
      const remaining = await scan(projectDir, { includeDev: opts.dev });
      if (opts.json) console.log(JSON.stringify({ results, remaining }, null, 2));
      else console.log(formatFixSummary(results, remaining));
      process.exitCode = results.some((r) => r.status !== "fixed") ? 1 : 0;
    },
  );

program.parseAsync().catch((err: unknown) => {
  console.error(pc.red(err instanceof Error ? err.message : String(err)));
  process.exitCode = 2;
});
