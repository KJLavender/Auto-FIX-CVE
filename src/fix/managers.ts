import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import { listSourceFiles } from "../impact/analyze.js";
import { importNames, listPythonFiles } from "../impact/python.js";
import { readLockfile, type LockKind } from "../lockfile/index.js";
import { requirementName } from "../lockfile/python.js";
import type { Dependency } from "../types.js";
import { normalizeName } from "../versions.js";
import { changelogExcerpt, exportShape } from "./context.js";
import { run, runFile, type CommandResult } from "./exec.js";

/** What the upgrade loop needs from a package manager. */
export interface PackageManager {
  /** Shown to the model, e.g. "JavaScript/TypeScript". */
  language: string;
  /** Files the upgrade may rewrite; snapshotted for rollback. */
  manifestFiles: string[];
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

class NpmManager implements PackageManager {
  language = "JavaScript/TypeScript";
  manifestFiles = ["package.json", "package-lock.json"];
  constructor(private readonly dir: string) {}

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
      // Key the override on the exact vulnerable version, so other copies of the
      // package (e.g. an unrelated older major) are left alone.
      json.overrides = { ...json.overrides, [`${dep.name}@${dep.version}`]: to };
    }
    await writeFile(path.join(this.dir, "package.json"), JSON.stringify(json, null, detectIndent(text)) + "\n", "utf8");
  }

  install() {
    return run("npm install", this.dir);
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

// ---------------------------------------------------------------- uv

const SHAPE_PY = [
  "import importlib, sys",
  "for name in sys.argv[1:]:",
  "    try:",
  "        m = importlib.import_module(name)",
  "        print(name + ': ' + ', '.join(sorted(n for n in dir(m) if not n.startswith('_'))[:80]))",
  "    except Exception as e:",
  "        print(name + ': import fails: ' + repr(e))",
].join("\n");

/** Splits a PEP 508 requirement into name (with extras), version spec and marker. */
export function splitRequirement(req: string): { head: string; spec: string; marker: string } {
  const [main, ...marker] = req.split(";");
  const m = main.trim().match(/^([A-Za-z0-9][A-Za-z0-9._-]*(?:\s*\[[^\]]*\])?)\s*(.*)$/);
  return { head: m?.[1] ?? main.trim(), spec: (m?.[2] ?? "").trim(), marker: marker.length ? `;${marker.join(";")}` : "" };
}

class UvManager implements PackageManager {
  language = "Python";
  manifestFiles = ["pyproject.toml", "uv.lock"];
  constructor(private readonly dir: string) {}

  private file() {
    return path.join(this.dir, "pyproject.toml");
  }

  /** Every requirement string in pyproject.toml that names the package. */
  private async requirements(name: string): Promise<string[]> {
    const doc = parseToml(await readFile(this.file(), "utf8")) as Record<string, any>;
    const all: unknown[] = [
      ...(doc.project?.dependencies ?? []),
      ...Object.values(doc.project?.["optional-dependencies"] ?? {}).flat(),
      ...Object.values(doc["dependency-groups"] ?? {}).flat(),
    ];
    return all.filter((r): r is string => typeof r === "string" && normalizeName("PyPI", requirementName(r) ?? "") === name);
  }

  async declares(dep: Dependency): Promise<boolean> {
    return (await this.requirements(dep.name)).length > 0;
  }

  async require(dep: Dependency, to: string, direct: boolean, exact: boolean): Promise<void> {
    let text = await readFile(this.file(), "utf8");
    if (direct) {
      for (const old of await this.requirements(dep.name)) {
        const { head, spec, marker } = splitRequirement(old);
        // A pinned requirement stays pinned; a range becomes a floor at the fixed version.
        const next = `${head}${exact || spec.startsWith("==") ? "==" : ">="}${to}${marker}`;
        text = text.split(`"${old}"`).join(`"${next}"`).split(`'${old}'`).join(`'${next}'`);
      }
    } else {
      // Python installs one version per package, so a constraint is the override.
      const entry = `"${dep.name}${exact ? "==" : ">="}${to}"`;
      const existing = text.match(/^constraint-dependencies\s*=\s*\[([\s\S]*?)\]/m);
      if (existing) {
        const items = existing[1].trim().replace(/,\s*$/, "");
        text = text.replace(existing[0], `constraint-dependencies = [${items ? `${items}, ` : ""}${entry}]`);
      } else if (/^\[tool\.uv\]\s*$/m.test(text)) {
        text = text.replace(/^\[tool\.uv\]\s*$/m, `[tool.uv]\nconstraint-dependencies = [${entry}]`);
      } else {
        text = `${text.replace(/\s*$/, "")}\n\n[tool.uv]\nconstraint-dependencies = [${entry}]\n`;
      }
    }
    await writeFile(this.file(), text, "utf8");
  }

  async install(): Promise<CommandResult> {
    const lock = await run("uv lock", this.dir);
    if (!lock.ok) return lock;
    return run("uv sync --all-groups", this.dir);
  }

  async lockedVersions(name: string): Promise<string[]> {
    return (await readLockfile(this.dir)).deps.filter((d) => d.name === name).map((d) => d.version);
  }

  async exportShape(name: string): Promise<string> {
    const modules = (await importNames(this.dir, [name])).get(name) ?? [];
    const res = await runFile("uv", ["run", "--no-sync", "python", "-c", SHAPE_PY, ...modules], this.dir);
    return res.output.trim();
  }

  async changelog(): Promise<string | undefined> {
    return undefined;
  }

  sourceFiles() {
    return listPythonFiles(this.dir);
  }
}

/** Package managers `fix` can drive; others can be scanned but not fixed yet. */
export const FIXABLE: LockKind[] = ["npm", "uv"];

export function managerFor(kind: LockKind, dir: string): PackageManager {
  if (kind === "npm") return new NpmManager(dir);
  if (kind === "uv") return new UvManager(dir);
  throw new Error(`fix does not support ${kind} projects yet`);
}

export function hasFile(dir: string, file: string): boolean {
  return existsSync(path.join(dir, file));
}
