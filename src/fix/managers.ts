import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import { listSourceFiles } from "../impact/analyze.js";
import { listGoFiles } from "../impact/go.js";
import { listRustFiles } from "../impact/rust.js";
import { readLockfile, type LockKind } from "../lockfile/index.js";
import type { Dependency } from "../types.js";
import { changelogExcerpt, exportShape } from "./context.js";
import { run, type CommandResult } from "./exec.js";
import { rewriteTableEntries } from "./toml-edit.js";
import { NugetManager } from "./nuget-manager.js";
import { PipenvManager, PoetryManager, UvManager } from "./python-managers.js";

export { splitRequirement } from "./python-managers.js";

/** What the upgrade loop needs from a package manager. */
export interface PackageManager {
  /** Shown to the model, e.g. "JavaScript/TypeScript". */
  language: string;
  /** Files the upgrade may rewrite; snapshotted for rollback. */
  manifestFiles: string[];
  /** Whether a transitive package can be forced to a version (overrides / constraints). */
  canOverride: boolean;
  /** Whether the project declares this package itself (vs. pulling it in transitively). */
  declares(dep: Dependency): Promise<boolean>;
  /**
   * Requires `to` for the package: in the manifest when declared, otherwise as
   * an override/constraint on the transitive copy. `exact` pins the version.
   */
  require(dep: Dependency, to: string, direct: boolean, exact: boolean): Promise<void>;
  install(): Promise<CommandResult>;
  /** Version the lockfile now resolves for the package, if any. */
  lockedVersions(name: string): Promise<string[]>;
  exportShape(name: string): Promise<string>;
  changelog(name: string, from: string): Promise<string | undefined>;
  sourceFiles(): Promise<string[]>;
}

// ---------------------------------------------------------------- npm

const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

function detectIndent(json: string): string | number {
  return json.match(/^[ \t]+(?=")/m)?.[0] ?? 2;
}

/** npm, pnpm and Yarn share package.json and node_modules; they differ in install and overrides. */
class JsManager implements PackageManager {
  language = "JavaScript/TypeScript";
  canOverride = true;
  manifestFiles = ["package.json", "package-lock.json"];
  protected installCommand = "npm install";
  constructor(protected readonly dir: string) {}

  /**
   * Forces the vulnerable transitive copy to `to`. Keyed on the exact vulnerable
   * version, so other copies of the package (e.g. an older major) are left alone.
   */
  protected override(json: Record<string, any>, dep: Dependency, to: string): void {
    json.overrides = { ...json.overrides, [`${dep.name}@${dep.version}`]: to };
  }

  private async pkg() {
    const text = await readFile(path.join(this.dir, "package.json"), "utf8");
    return { text, json: JSON.parse(text) as Record<string, any> };
  }

  async declares(dep: Dependency): Promise<boolean> {
    const { json } = await this.pkg();
    return DEP_FIELDS.some((f) => json[f]?.[dep.name] !== undefined);
  }

  async require(dep: Dependency, to: string, direct: boolean, exact: boolean): Promise<void> {
    const { text, json } = await this.pkg();
    const field = DEP_FIELDS.find((f) => json[f]?.[dep.name] !== undefined);
    if (direct && field) {
      // Keep the project's range style (^ / ~) unless an exact pin is needed.
      const prefix = exact ? "" : (String(json[field][dep.name]).match(/^[\^~]/)?.[0] ?? "");
      json[field][dep.name] = prefix + to;
    } else {
      this.override(json, dep, to);
    }
    await writeFile(path.join(this.dir, "package.json"), JSON.stringify(json, null, detectIndent(text)) + "\n", "utf8");
  }

  install() {
    return run(this.installCommand, this.dir);
  }

  async lockedVersions(name: string): Promise<string[]> {
    return (await readLockfile(this.dir)).deps.filter((d) => d.name === name).map((d) => d.version);
  }

  exportShape(name: string) {
    return exportShape(this.dir, name);
  }

  changelog(name: string, from: string) {
    return changelogExcerpt(this.dir, name, from);
  }

  sourceFiles() {
    return listSourceFiles(this.dir);
  }
}

class PnpmManager extends JsManager {
  manifestFiles = ["package.json", "pnpm-lock.yaml"];
  // Child commands run with CI=1, where pnpm defaults to a frozen lockfile.
  protected installCommand = `${process.env.AUTOFIX_PNPM ?? "pnpm"} install --no-frozen-lockfile`;

  // pnpm supports the same exact-version selector under its own key.
  protected override(json: Record<string, any>, dep: Dependency, to: string): void {
    json.pnpm = { ...json.pnpm, overrides: { ...json.pnpm?.overrides, [`${dep.name}@${dep.version}`]: to } };
  }
}

class YarnManager extends JsManager {
  // Yarn resolutions cannot target one version of a package, so forcing a
  // transitive copy could break other consumers; only declared packages are fixed.
  canOverride = false;
  manifestFiles = ["package.json", "yarn.lock"];
  protected installCommand = `${process.env.AUTOFIX_YARN ?? "yarn"} install`;

  async install() {
    // Yarn Berry makes the lockfile immutable under CI=1; classic Yarn has no such flag.
    const berry = (await readFile(path.join(this.dir, "yarn.lock"), "utf8")).includes("__metadata:");
    return run(berry ? `${this.installCommand} --no-immutable` : this.installCommand, this.dir);
  }
}

/**
 * Go modules: go.mod lists every module in the build, so both direct and
 * indirect requirements are raised in place and `go mod tidy` settles go.sum.
 * Minimal version selection keeps the raised version.
 */
class GoManager implements PackageManager {
  language = "Go";
  canOverride = true;
  manifestFiles = ["go.mod", "go.sum"];
  private readonly go = process.env.AUTOFIX_GO ?? "go";
  constructor(private readonly dir: string) {}

  private file() {
    return path.join(this.dir, "go.mod");
  }

  async declares(dep: Dependency): Promise<boolean> {
    return dep.direct;
  }

  async require(dep: Dependency, to: string): Promise<void> {
    const text = await readFile(this.file(), "utf8");
    const lines = text.split("\n");
    let found = false;
    const next = lines.map((line) => {
      const words = line.trim().split(/\s+/);
      const [mod, ver] = words[0] === "require" ? words.slice(1) : words;
      if (mod !== dep.name || !ver?.startsWith("v")) return line;
      found = true;
      return line.replace(ver, to);
    });
    // Not required yet (pulled in only through go.sum): add an explicit requirement.
    if (!found) next.push(`require ${dep.name} ${to}`);
    await writeFile(this.file(), next.join("\n"), "utf8");
  }

  install(): Promise<CommandResult> {
    return run(`${this.go} mod tidy`, this.dir);
  }

  async lockedVersions(name: string): Promise<string[]> {
    return (await readLockfile(this.dir)).deps.filter((d) => d.name === name).map((d) => d.version);
  }

  async exportShape(name: string): Promise<string> {
    const res = await run(`${this.go} doc -short ${name}`, this.dir);
    return res.output.trim().split("\n").slice(0, 80).join("\n");
  }

  async changelog(): Promise<string | undefined> {
    return undefined;
  }

  sourceFiles() {
    return listGoFiles(this.dir);
  }
}

/** Cargo requirement for the fix: an exact pin (`=x`) stays exact, anything else becomes a caret floor. */
export function cargoRequirement(old: string, to: string, exact: boolean): string {
  return exact || old.trim().startsWith("=") ? `=${to}` : to;
}

/**
 * Rust: declared crates get a new requirement in Cargo.toml; a transitive crate
 * is moved with `cargo update --precise`, which only touches Cargo.lock and
 * fails (triggering a rollback) if the new version breaks another crate's requirement.
 */
class CargoManager implements PackageManager {
  language = "Rust";
  canOverride = true;
  manifestFiles = ["Cargo.toml", "Cargo.lock"];
  private readonly cargo = process.env.AUTOFIX_CARGO ?? "cargo";
  private pending: string[] = [];
  constructor(private readonly dir: string) {}

  private file() {
    return path.join(this.dir, "Cargo.toml");
  }

  private async keys(name: string): Promise<string[]> {
    const doc = parseToml(await readFile(this.file(), "utf8")) as Record<string, any>;
    const tables = [doc.dependencies, doc["dev-dependencies"], doc["build-dependencies"]];
    return tables.flatMap((t) => Object.keys(t ?? {})).filter((k) => k === name);
  }

  async declares(dep: Dependency): Promise<boolean> {
    return (await this.keys(dep.name)).length > 0;
  }

  async require(dep: Dependency, to: string, direct: boolean, exact: boolean): Promise<void> {
    if (direct) {
      const text = await readFile(this.file(), "utf8");
      await writeFile(this.file(), rewriteTableEntries(text, await this.keys(dep.name), (old) => cargoRequirement(old, to, exact)), "utf8");
      this.pending.push(`${this.cargo} update -p ${dep.name}`);
    } else {
      this.pending.push(`${this.cargo} update -p ${dep.name}@${dep.version} --precise ${to}`);
    }
  }

  async install(): Promise<CommandResult> {
    // Nothing pending (e.g. a rollback restored Cargo.lock): fetch what the lockfile says, without re-resolving.
    const commands = this.pending.length ? this.pending : [`${this.cargo} fetch`];
    this.pending = [];
    let last: CommandResult = { ok: true, output: "" };
    for (const command of commands) {
      last = await run(command, this.dir);
      if (!last.ok) return last;
    }
    return last;
  }

  async lockedVersions(name: string): Promise<string[]> {
    return (await readLockfile(this.dir)).deps.filter((d) => d.name === name).map((d) => d.version);
  }

  async exportShape(): Promise<string> {
    return "";
  }

  async changelog(): Promise<string | undefined> {
    return undefined;
  }

  sourceFiles() {
    return listRustFiles(this.dir);
  }
}

/** Package managers `fix` can drive; others can be scanned but not fixed yet. */
export const FIXABLE: LockKind[] = ["npm", "pnpm", "yarn", "uv", "poetry", "pipenv", "go", "cargo", "nuget"];

export function managerFor(kind: LockKind, dir: string): PackageManager {
  if (kind === "npm") return new JsManager(dir);
  if (kind === "pnpm") return new PnpmManager(dir);
  if (kind === "yarn") return new YarnManager(dir);
  if (kind === "go") return new GoManager(dir);
  if (kind === "cargo") return new CargoManager(dir);
  if (kind === "nuget") return new NugetManager(dir);
  if (kind === "uv") return new UvManager(dir);
  if (kind === "poetry") return new PoetryManager(dir);
  if (kind === "pipenv") return new PipenvManager(dir);
  throw new Error(`fix does not support ${kind} projects yet`);
}

