import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { listSourceFiles } from "../impact/analyze.js";
import { readLockfile, type LockKind } from "../lockfile/index.js";
import type { Dependency } from "../types.js";
import { changelogExcerpt, exportShape } from "./context.js";
import { run, type CommandResult } from "./exec.js";
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

/** Package managers `fix` can drive; others can be scanned but not fixed yet. */
export const FIXABLE: LockKind[] = ["npm", "pnpm", "yarn", "uv", "poetry", "pipenv"];

export function managerFor(kind: LockKind, dir: string): PackageManager {
  if (kind === "npm") return new JsManager(dir);
  if (kind === "pnpm") return new PnpmManager(dir);
  if (kind === "yarn") return new YarnManager(dir);
  if (kind === "uv") return new UvManager(dir);
  if (kind === "poetry") return new PoetryManager(dir);
  if (kind === "pipenv") return new PipenvManager(dir);
  throw new Error(`fix does not support ${kind} projects yet`);
}

