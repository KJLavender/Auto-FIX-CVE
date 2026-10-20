/**
 * Runs `fix` on every case in bench/cases and records what happened.
 *
 *   npm run bench              # all cases
 *   npm run bench -- js-marked # selected cases
 *
 * Each case is copied to a temp dir, installed, committed to a throwaway git
 * repo (so source changes can be measured), then fixed with `--yes --json`.
 * This calls the LLM and costs a few cents per case.
 */
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const CASES = path.join(ROOT, "bench", "cases");
const CLI = path.join(ROOT, "dist", "cli.js");

interface FixResult {
  package: string;
  from: string;
  to?: string;
  strategy: string;
  status: string;
  attempts: number;
  fixedVulns: string[];
  costUsd: number;
  reason?: string;
}

interface Row {
  name: string;
  before: number;
  after: number;
  change: string;
  status: string;
  rounds: number;
  sourceLines: string;
  cost: number;
  seconds: number;
}

function sh(cmd: string, cwd: string): { ok: boolean; out: string } {
  const res = spawnSync(cmd, { cwd, shell: true, encoding: "utf8", env: { ...process.env, NO_COLOR: "1", CI: "1" } });
  return { ok: res.status === 0, out: `${res.stdout ?? ""}${res.stderr ?? ""}` };
}

function countVulns(dir: string): number {
  const res = spawnSync(process.execPath, [CLI, "scan", dir, "--json"], { encoding: "utf8" });
  const findings = JSON.parse(res.stdout || "[]") as { vulns: unknown[] }[];
  return findings.reduce((n, f) => n + f.vulns.length, 0);
}

function runCase(name: string): Row {
  const dir = mkdtempSync(path.join(tmpdir(), `bench-${name}-`));
  cpSync(path.join(CASES, name), dir, {
    recursive: true,
    filter: (src) => !/[\\/](node_modules|\.venv)([\\/]|$)/.test(src),
  });
  const poetry = process.env.AUTOFIX_POETRY ?? "poetry";
  const install = sh(
    existsSync(path.join(dir, "uv.lock"))
      ? "uv sync --all-groups -q"
      : existsSync(path.join(dir, "poetry.lock"))
        ? `${poetry} install --all-groups --no-root -q`
        : "npm install --ignore-scripts --no-audit --no-fund",
    dir,
  );
  if (!install.ok) throw new Error(`${name}: install failed\n${install.out}`);
  writeFileSync(path.join(dir, ".gitignore"), "node_modules/\n.venv/\n__pycache__/\n.pytest_cache/\n");
  sh("git init -q && git add -A && git -c user.name=bench -c user.email=bench@localhost commit -q -m base", dir);

  const before = countVulns(dir);
  const started = Date.now();
  const res = spawnSync(process.execPath, [CLI, "fix", dir, "--yes", "--json"], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  const seconds = (Date.now() - started) / 1000;
  // Keep the full output next to the case so a missing result can be explained.
  const log = path.join(tmpdir(), `bench-${name}.log`);
  writeFileSync(log, `exit ${res.status} ${res.error ?? ""}\n--- stdout\n${res.stdout}\n--- stderr\n${res.stderr}`);
  if (!res.stdout.trim()) throw new Error(`${name}: fix printed no JSON (exit ${res.status}); see ${log}`);
  const { results } = JSON.parse(res.stdout) as { results: FixResult[] };
  const after = countVulns(dir);

  // Lines of the project's own code the model changed (manifests and lockfiles excluded).
  const stat = sh("git diff --numstat -- . \":(exclude)package.json\" \":(exclude)package-lock.json\" \":(exclude)pyproject.toml\" \":(exclude)uv.lock\" \":(exclude)poetry.lock\"", dir).out;
  const [added, removed] = stat
    .split(/\r?\n/)
    // git also prints warnings (e.g. about line endings) on the same stream; keep only numstat rows.
    .filter((line) => /^\d+\t\d+\t/.test(line))
    .reduce(([a, r], line) => {
      const [x, y] = line.split("\t");
      return [a + Number(x || 0), r + Number(y || 0)];
    }, [0, 0]);

  return {
    name,
    before,
    after,
    change: results.map((r) => `${r.package} ${r.from} → ${r.to ?? "?"}`).join(", "),
    status: results.map((r) => r.status + (r.reason ? ` (${r.reason.split("\n")[0]})` : "")).join(", "),
    rounds: results.reduce((n, r) => n + r.attempts, 0),
    sourceLines: added + removed ? `+${added} −${removed}` : "none",
    cost: results.reduce((n, r) => n + r.costUsd, 0),
    seconds,
  };
}

const selected = process.argv.slice(2);
const names = readdirSync(CASES).filter((n) => !selected.length || selected.includes(n));
const rows: Row[] = [];
for (const name of names) {
  process.stderr.write(`running ${name}…\n`);
  try {
    rows.push(runCase(name));
  } catch (e) {
    process.stderr.write(`${e instanceof Error ? e.message : e}\n`);
  }
}

const table = [
  "| Case | Upgrade | Vulns before → after | Result | Model rounds | Source lines changed | Cost | Time |",
  "|---|---|---|---|---|---|---|---|",
  ...rows.map(
    (r) =>
      `| ${r.name} | ${r.change} | ${r.before} → ${r.after} | ${r.status} | ${r.rounds} | ${r.sourceLines} | $${r.cost.toFixed(3)} | ${r.seconds.toFixed(0)}s |`,
  ),
].join("\n");
console.log(table);
if (!selected.length) {
  writeFileSync(
    path.join(ROOT, "bench", "RESULTS.md"),
    `# Benchmark results\n\nGenerated by \`npm run bench\` on ${new Date().toISOString().slice(0, 10)}.\n\n${table}\n`,
  );
}
