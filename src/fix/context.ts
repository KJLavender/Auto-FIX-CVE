import { existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { listSourceFiles } from "../impact/analyze.js";
import type { LockKind } from "../lockfile/index.js";
import type { Usage } from "../types.js";
import { runFile } from "./exec.js";

const DEFAULT_TEST = /no test specified/;

/** Picks verification commands for the project, cheapest first, using its own package manager. */
export async function detectChecks(projectDir: string, kind: LockKind): Promise<string[]> {
  if (kind === "uv") return detectPythonChecks(projectDir, "uv run");
  if (kind === "poetry") return detectPythonChecks(projectDir, `${process.env.AUTOFIX_POETRY ?? "poetry"} run`);
  if (kind === "pipenv") return detectPythonChecks(projectDir, `${process.env.AUTOFIX_PIPENV ?? "pipenv"} run`, "Pipfile");
  if (kind === "requirements") return [];
  if (kind === "cargo") {
    const cargo = process.env.AUTOFIX_CARGO ?? "cargo";
    return [`${cargo} build`, `${cargo} test`];
  }
  if (kind === "go") {
    const go = process.env.AUTOFIX_GO ?? "go";
    return [`${go} build ./...`, `${go} test ./...`];
  }

  // `yarn test` also works under Plug'n'Play, where plain node cannot resolve packages.
  const runner = kind === "pnpm" ? (process.env.AUTOFIX_PNPM ?? "pnpm") : kind === "yarn" ? (process.env.AUTOFIX_YARN ?? "yarn") : "npm";
  const pkg = JSON.parse(await readFile(path.join(projectDir, "package.json"), "utf8")) as {
    scripts?: Record<string, string>;
  };
  const scripts = pkg.scripts ?? {};
  const checks: string[] = [];
  if (scripts.typecheck) checks.push(`${runner} run typecheck`);
  else if (existsSync(path.join(projectDir, "tsconfig.json")) && existsSync(path.join(projectDir, "node_modules/.bin/tsc"))) {
    checks.push("npx tsc --noEmit");
  }
  if (scripts.build) checks.push(`${runner} run build`);
  if (scripts.test && !DEFAULT_TEST.test(scripts.test)) checks.push(`${runner} test`);
  return checks;
}

/** pytest when the project uses it (mentioned in pyproject.toml, or a tests/ directory). */
async function detectPythonChecks(projectDir: string, runner: string, manifest = "pyproject.toml"): Promise<string[]> {
  const pyproject = existsSync(path.join(projectDir, manifest)) ? await readFile(path.join(projectDir, manifest), "utf8") : "";
  const usesPytest =
    /\bpytest\b/.test(pyproject) || existsSync(path.join(projectDir, "tests")) || existsSync(path.join(projectDir, "test"));
  return usesPytest ? [`${runner} pytest -q`] : [];
}

const SHAPE_SCRIPT = `
const name = process.argv[1];
const describe = (m) => {
  const t = typeof m;
  const keys = m && (t === "object" || t === "function") ? Object.keys(m).slice(0, 60) : [];
  return t + (keys.length ? " with keys: " + keys.join(", ") : "");
};
const out = [];
try { out.push("require(): " + describe(require(name))); }
catch (e) { out.push("require() throws " + (e.code || e.message)); }
import(name)
  .then((m) => out.push("import(): namespace with keys: " + Object.keys(m).join(", ") +
    (m.default !== undefined ? "; default export is " + describe(m.default) : "")))
  .catch((e) => out.push("import() throws " + (e.code || e.message)))
  .finally(() => console.log(out.join("\\n")));
`;

/**
 * Describes what the installed package exports at runtime. Comparing this
 * before and after an upgrade shows removed or reshaped exports directly.
 */
export async function exportShape(projectDir: string, pkg: string): Promise<string> {
  const res = await runFile(process.execPath, ["-e", SHAPE_SCRIPT, pkg], projectDir);
  return res.output.trim();
}

const CHANGELOG = /^(changelog|history|changes|release[-_]?notes)(\.(md|markdown|txt))?$/i;

/** Returns the installed package's changelog, cut off where `fromVersion` begins. */
export async function changelogExcerpt(projectDir: string, pkg: string, fromVersion: string, max = 12000): Promise<string | undefined> {
  const dir = path.join(projectDir, "node_modules", pkg);
  if (!existsSync(dir)) return undefined;
  const file = (await readdir(dir)).find((f) => CHANGELOG.test(f));
  if (!file) return undefined;
  const text = await readFile(path.join(dir, file), "utf8");
  const lines = text.split(/\r?\n/);
  const stop = lines.findIndex((l) => /^(#|\[|v?\d)/.test(l.trim()) && l.includes(fromVersion));
  const excerpt = (stop > 0 ? lines.slice(0, stop) : lines).join("\n");
  return excerpt.length > max ? `${excerpt.slice(0, max)}\n…(truncated)` : excerpt;
}

/** Source files that use the package or appear in the failing output. */
export async function relevantFiles(
  projectDir: string,
  usages: Usage[],
  failureOutput: string,
  sourceFiles: string[],
  maxFiles = 12,
): Promise<string[]> {
  const files = new Set(usages.map((u) => u.file));
  const normalized = failureOutput.replace(/\\/g, "/");
  for (const abs of sourceFiles) {
    const rel = path.relative(projectDir, abs).split(path.sep).join("/");
    if (normalized.includes(rel)) files.add(rel);
  }
  return [...files].slice(0, maxFiles);
}
