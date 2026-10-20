import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Dependency } from "../types.js";

interface Requirement {
  module: string;
  version: string;
  indirect: boolean;
}

/** One `module version [// indirect]` entry, from a `require (...)` block or a single-line require. */
function parseRequireLine(line: string): Requirement | undefined {
  const m = line.match(/^\s*([^\s/][^\s]*)\s+(v[^\s]+)(.*)$/);
  if (!m) return undefined;
  return { module: m[1], version: m[2], indirect: /\/\/\s*indirect\b/.test(m[3]) };
}

/**
 * Reads go.mod. Since Go 1.17 it lists every module in the build, marking the
 * ones the project does not import itself as `// indirect`. go.mod does not say
 * which module needs an indirect one, so those carry no `introducedBy`.
 * `replace` directives are applied, since the replacement is what gets built.
 */
export function parseGoMod(text: string): Dependency[] {
  const requires: Requirement[] = [];
  const replaces = new Map<string, { module: string; version?: string }>();
  let block: "require" | "replace" | undefined;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^\s+/, "");
    if (block && line.startsWith(")")) {
      block = undefined;
      continue;
    }
    const open = line.match(/^(require|replace)\s*\($/);
    if (open) {
      block = open[1] as "require" | "replace";
      continue;
    }
    const single = line.match(/^(require|replace)\s+(.*)$/);
    const kind = single ? (single[1] as "require" | "replace") : block;
    const body = single ? single[2] : line;
    if (kind === "require") {
      const req = parseRequireLine(body);
      if (req) requires.push(req);
    } else if (kind === "replace") {
      // `old [version] => new [version]`; local paths (./x) have no version and are skipped.
      const m = body.match(/^(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(v\S+))?/);
      if (m && !m[2].startsWith(".") && !m[2].startsWith("/")) replaces.set(m[1], { module: m[2], version: m[3] });
    }
  }

  return requires.map((r) => {
    const rep = replaces.get(r.module);
    const module = rep?.module ?? r.module;
    const version = rep?.version ?? r.version;
    return {
      ecosystem: "Go",
      name: module,
      version,
      paths: [],
      direct: !r.indirect,
      dev: false,
      introducedBy: r.indirect ? [] : [module],
    };
  });
}

export async function readGoMod(projectDir: string): Promise<Dependency[]> {
  return parseGoMod(await readFile(path.join(projectDir, "go.mod"), "utf8"));
}
