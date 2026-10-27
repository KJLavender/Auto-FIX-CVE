import { existsSync, readdirSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { listCsFiles } from "../impact/csharp.js";
import { detectLockfiles, readLockfile } from "../lockfile/index.js";
import type { Dependency } from "../types.js";
import { run, type CommandResult } from "./exec.js";
import type { PackageManager } from "./managers.js";

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** `<Tag Include="Id" … Version="x" … />` (or `Update=`), matching the id case-insensitively. */
function itemPattern(tag: string, id: string): RegExp {
  return new RegExp(`<${tag}\\s+(?:[^>]*?\\s)?(?:Include|Update)\\s*=\\s*"${escapeRegExp(id)}"[^>]*?>`, "gi");
}

/** Sets the Version of matching items, as an attribute or a `<Version>` child element. */
export function setItemVersion(xml: string, tag: string, id: string, version: string): { xml: string; changed: boolean } {
  let changed = false;
  let out = xml.replace(itemPattern(tag, id), (open) => {
    if (!/\sVersion\s*=/i.test(open)) return open;
    changed = true;
    return open.replace(/(\sVersion\s*=\s*")[^"]*(")/i, `$1${version}$2`);
  });
  // <PackageReference Include="X"><Version>1.0</Version></PackageReference>
  const element = new RegExp(`(<${tag}\\s+[^>]*?(?:Include|Update)\\s*=\\s*"${escapeRegExp(id)}"[^/>]*>\\s*<Version>)[^<]*(</Version>)`, "gi");
  out = out.replace(element, (_, a: string, b: string) => {
    changed = true;
    return `${a}${version}${b}`;
  });
  return { xml: out, changed };
}

/** Adds an item to the first ItemGroup that already holds `tag` items, or to a new ItemGroup. */
export function addItem(xml: string, tag: string, attributes: string): string {
  const item = `<${tag} ${attributes} />`;
  const group = new RegExp(`(<ItemGroup[^>]*>)([\\s\\S]*?)(\\n?([ \\t]*)<${tag}\\b)`).exec(xml);
  if (group) {
    const indent = group[4] || "    ";
    const at = group.index + group[1].length + group[2].length + (group[3].startsWith("\n") ? 1 : 0);
    return `${xml.slice(0, at)}${indent}${item}\n${xml.slice(at)}`;
  }
  const close = xml.lastIndexOf("</Project>");
  if (close === -1) throw new Error("not an MSBuild project file");
  return `${xml.slice(0, close)}  <ItemGroup>\n    ${item}\n  </ItemGroup>\n${xml.slice(close)}`;
}

/**
 * .NET projects. A package the project references gets its Version raised
 * (in the .csproj, or in Directory.Packages.props with Central Package
 * Management). A transitive package is pinned the way NuGet intends: by
 * referencing it directly at the fixed version, which wins over what other
 * packages ask for. `dotnet restore` then resolves, and fails if that conflicts.
 */
export class NugetManager implements PackageManager {
  language = "C#/.NET";
  canOverride = true;
  /** Snapshotted for rollback: the project file, Directory.Packages.props and the lockfile. */
  manifestFiles: string[];
  private readonly dotnet = process.env.AUTOFIX_DOTNET ?? "dotnet";
  private readonly project: string;
  private props?: string;

  /** Finds the project file and, walking up to the repo root, a Directory.Packages.props. */
  constructor(private readonly dir: string) {
    const projects = readdirSync(dir).filter((f) => /\.(cs|fs|vb)proj$/.test(f));
    if (projects.length !== 1) throw new Error(`expected one project file in ${dir}, found ${projects.length ? projects.join(", ") : "none"}`);
    this.project = projects[0];
    for (let d = dir, i = 0; i < 6; i++) {
      const candidate = path.join(d, "Directory.Packages.props");
      if (existsSync(candidate)) {
        this.props = path.relative(dir, candidate);
        break;
      }
      if (existsSync(path.join(d, ".git")) || path.dirname(d) === d) break;
      d = path.dirname(d);
    }
    const lock = detectLockfiles(dir).find((l) => l.kind === "nuget");
    this.manifestFiles = [this.project, ...(this.props ? [this.props] : []), ...(lock ? [lock.file] : [])];
  }

  private read(file: string) {
    return readFile(path.join(this.dir, file), "utf8");
  }

  private write(file: string, text: string) {
    return writeFile(path.join(this.dir, file), text, "utf8");
  }

  async declares(dep: Dependency): Promise<boolean> {
    return itemPattern("PackageReference", dep.name).test(await this.read(this.project));
  }

  async require(dep: Dependency, to: string, direct: boolean): Promise<void> {
    const csproj = await this.read(this.project);
    if (this.props) {
      // Central Package Management: versions live in Directory.Packages.props.
      const props = await this.read(this.props);
      const set = setItemVersion(props, "PackageVersion", dep.name, to);
      await this.write(this.props, set.changed ? set.xml : addItem(props, "PackageVersion", `Include="${dep.name}" Version="${to}"`));
      if (!direct) await this.write(this.project, addItem(csproj, "PackageReference", `Include="${dep.name}"`));
      return;
    }
    const set = setItemVersion(csproj, "PackageReference", dep.name, to);
    if (direct && set.changed) await this.write(this.project, set.xml);
    else await this.write(this.project, addItem(csproj, "PackageReference", `Include="${dep.name}" Version="${to}"`));
  }

  async install(): Promise<CommandResult> {
    // --force-evaluate rewrites packages.lock.json instead of failing on the now-stale lock.
    const lock = this.manifestFiles.includes("packages.lock.json") ? " --force-evaluate" : "";
    return run(`${this.dotnet} restore${lock}`, this.dir);
  }

  async lockedVersions(name: string): Promise<string[]> {
    return (await readLockfile(this.dir)).deps.filter((d) => d.name.toLowerCase() === name.toLowerCase()).map((d) => d.version);
  }

  async exportShape(): Promise<string> {
    return "";
  }

  async changelog(): Promise<string | undefined> {
    return undefined;
  }

  sourceFiles() {
    return listCsFiles(this.dir);
  }
}
