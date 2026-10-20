import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import { importNames, listPythonFiles } from "../impact/python.js";
import { readLockfile } from "../lockfile/index.js";
import { requirementName } from "../lockfile/python.js";
import type { Dependency } from "../types.js";
import { normalizeName } from "../versions.js";
import { run, type CommandResult } from "./exec.js";
import type { PackageManager } from "./managers.js";

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

/** PEP 621 / PEP 735 requirement strings in pyproject.toml that name the package. */
function pep621Requirements(doc: Record<string, any>, name: string): string[] {
  const all: unknown[] = [
    ...(doc.project?.dependencies ?? []),
    ...Object.values(doc.project?.["optional-dependencies"] ?? {}).flat(),
    ...Object.values(doc["dependency-groups"] ?? {}).flat(),
  ];
  return all.filter((r): r is string => typeof r === "string" && normalizeName("PyPI", requirementName(r) ?? "") === name);
}

/** Rewrites the package's requirement strings: a pin stays pinned, a range becomes a floor at the fix. */
function rewritePep621(text: string, olds: string[], to: string, exact: boolean): string {
  for (const old of olds) {
    const { head, spec, marker } = splitRequirement(old);
    const next = `${head}${exact || spec.startsWith("==") ? "==" : ">="}${to}${marker}`;
    text = text.split(`"${old}"`).join(`"${next}"`).split(`'${old}'`).join(`'${next}'`);
  }
  return text;
}

/** Imports the package's modules with the project's interpreter and lists their public names. */
async function pythonShape(dir: string, name: string, runner: string): Promise<string> {
  const modules = (await importNames(dir, [name])).get(name) ?? [];
  const script = path.join(await mkdtemp(path.join(tmpdir(), "autofix-shape-")), "shape.py");
  await writeFile(script, SHAPE_PY, "utf8");
  const res = await run(`${runner} python "${script}" ${modules.join(" ")}`, dir);
  return res.output.trim();
}

abstract class PythonManager implements PackageManager {
  language = "Python";
  abstract canOverride: boolean;
  abstract manifestFiles: string[];
  /** Command prefix that runs a program inside the project's environment. */
  protected abstract runner: string;
  constructor(protected readonly dir: string) {}

  protected file() {
    return path.join(this.dir, "pyproject.toml");
  }

  protected async doc(): Promise<Record<string, any>> {
    return parseToml(await readFile(this.file(), "utf8")) as Record<string, any>;
  }

  abstract declares(dep: Dependency): Promise<boolean>;
  abstract require(dep: Dependency, to: string, direct: boolean, exact: boolean): Promise<void>;
  abstract install(): Promise<CommandResult>;

  async lockedVersions(name: string): Promise<string[]> {
    return (await readLockfile(this.dir)).deps.filter((d) => d.name === name).map((d) => d.version);
  }

  exportShape(name: string): Promise<string> {
    return pythonShape(this.dir, name, this.runner);
  }

  async changelog(): Promise<string | undefined> {
    return undefined;
  }

  sourceFiles() {
    return listPythonFiles(this.dir);
  }
}

// ---------------------------------------------------------------- uv

export class UvManager extends PythonManager {
  canOverride = true;
  manifestFiles = ["pyproject.toml", "uv.lock"];
  protected runner = "uv run --no-sync";

  async declares(dep: Dependency): Promise<boolean> {
    return pep621Requirements(await this.doc(), dep.name).length > 0;
  }

  async require(dep: Dependency, to: string, direct: boolean, exact: boolean): Promise<void> {
    let text = await readFile(this.file(), "utf8");
    if (direct) {
      text = rewritePep621(text, pep621Requirements(await this.doc(), dep.name), to, exact);
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
}

// ---------------------------------------------------------------- shared table rewriting

/** Rewrites `key = "spec"` and `key = { version = "spec", ... }` lines for every matching key. */
function rewriteTableEntries(text: string, keys: string[], next: (old: string) => string): string {
  for (const key of keys) {
    const quoted = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    text = text.replace(new RegExp(`^(\\s*"?${quoted}"?\\s*=\\s*)"([^"]*)"`, "gm"), (_m, lead: string, old: string) => `${lead}"${next(old)}"`);
    text = text.replace(
      new RegExp(`^(\\s*"?${quoted}"?\\s*=\\s*\\{[^}\\n]*version\\s*=\\s*)"([^"]*)"`, "gm"),
      (_m, lead: string, old: string) => `${lead}"${next(old)}"`,
    );
  }
  return text;
}

// ---------------------------------------------------------------- Pipenv

const PIPENV = process.env.AUTOFIX_PIPENV ?? "pipenv";

/** Pipfile specifier for the fix: a pin stays pinned, anything else becomes a floor. */
export function pipfileSpecifier(old: string, to: string, exact: boolean): string {
  return exact || old.trim().startsWith("==") ? `==${to}` : `>=${to}`;
}

export class PipenvManager extends PythonManager {
  // Pipfile only lists what the project asks for; there is no way to force a transitive version.
  canOverride = false;
  manifestFiles = ["Pipfile", "Pipfile.lock"];
  protected runner = `${PIPENV} run`;

  private pipfile() {
    return path.join(this.dir, "Pipfile");
  }

  private async keys(name: string): Promise<string[]> {
    const doc = parseToml(await readFile(this.pipfile(), "utf8")) as Record<string, any>;
    const keys = [...Object.keys(doc.packages ?? {}), ...Object.keys(doc["dev-packages"] ?? {})];
    return [...new Set(keys.filter((k) => normalizeName("PyPI", k) === name))];
  }

  async declares(dep: Dependency): Promise<boolean> {
    return (await this.keys(dep.name)).length > 0;
  }

  async require(dep: Dependency, to: string, _direct: boolean, exact: boolean): Promise<void> {
    const text = await readFile(this.pipfile(), "utf8");
    const next = rewriteTableEntries(text, await this.keys(dep.name), (old) => pipfileSpecifier(old, to, exact));
    await writeFile(this.pipfile(), next, "utf8");
  }

  async install(): Promise<CommandResult> {
    const lock = await run(`${PIPENV} lock`, this.dir);
    if (!lock.ok) return lock;
    return run(`${PIPENV} sync --dev`, this.dir);
  }
}

// ---------------------------------------------------------------- Poetry

/** `poetry`, or e.g. `uvx poetry` when Poetry is not installed globally. */
const POETRY = process.env.AUTOFIX_POETRY ?? "poetry";

/** Keys of Poetry's own dependency tables whose names match the package. */
function poetryKeys(doc: Record<string, any>, name: string): string[] {
  const tables = [
    doc.tool?.poetry?.dependencies,
    doc.tool?.poetry?.["dev-dependencies"],
    ...Object.values(doc.tool?.poetry?.group ?? {}).map((g: any) => g?.dependencies),
  ];
  return [...new Set(tables.flatMap((t) => Object.keys(t ?? {})).filter((k) => normalizeName("PyPI", k) === name))];
}

/** Poetry constraint for the fix, keeping the project's style (pin, caret, tilde or floor). */
export function poetryConstraint(old: string, to: string, exact: boolean): string {
  if (exact || /^(==)?\d/.test(old.trim())) return to;
  if (old.trim().startsWith("^")) return `^${to}`;
  if (old.trim().startsWith("~")) return `~${to}`;
  return `>=${to}`;
}

export class PoetryManager extends PythonManager {
  // Poetry has no constraint/override mechanism for packages it does not declare.
  canOverride = false;
  manifestFiles = ["pyproject.toml", "poetry.lock"];
  protected runner = `${POETRY} run`;

  async declares(dep: Dependency): Promise<boolean> {
    const doc = await this.doc();
    return pep621Requirements(doc, dep.name).length > 0 || poetryKeys(doc, dep.name).length > 0;
  }

  async require(dep: Dependency, to: string, _direct: boolean, exact: boolean): Promise<void> {
    const doc = await this.doc();
    const withPep621 = rewritePep621(await readFile(this.file(), "utf8"), pep621Requirements(doc, dep.name), to, exact);
    const text = rewriteTableEntries(withPep621, poetryKeys(doc, dep.name), (old) => poetryConstraint(old, to, exact));
    await writeFile(this.file(), text, "utf8");
  }

  async install(): Promise<CommandResult> {
    const lock = await run(`${POETRY} lock`, this.dir);
    if (!lock.ok) return lock;
    return run(`${POETRY} install --all-groups --no-root`, this.dir);
  }
}
