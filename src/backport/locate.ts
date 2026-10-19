import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

const CODE_EXT = /\.(c|m)?js$/;
const MAX_FILE = 5 * 1024 * 1024;

export interface TargetFile {
  /** Path relative to the package directory. */
  file: string;
  /** Excerpts around the matched anchors, ready to show the model. */
  excerpt: string;
  matches: number;
}

async function listCode(dir: string, base = dir): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules") out.push(...(await listCode(abs, base)));
    } else if (CODE_EXT.test(entry.name) && (await stat(abs)).size <= MAX_FILE) {
      out.push(path.relative(base, abs).split(path.sep).join("/"));
    }
  }
  return out;
}

/**
 * Fragments to search for. Bundlers and minifiers change whitespace, so besides
 * the whole line we also try its longest whitespace-free run.
 */
export function anchorsFor(lines: string[]): string[] {
  const anchors = new Set<string>();
  for (const line of lines) {
    anchors.add(line);
    const longest = line.split(/\s+/).sort((a, b) => b.length - a.length)[0];
    if (longest && longest.length >= 12) anchors.add(longest);
  }
  return [...anchors];
}

function lineExcerpt(content: string, positions: number[], context = 25): string {
  const lines = content.split("\n");
  const lineOf = (pos: number) => content.slice(0, pos).split("\n").length - 1;
  const ranges = positions
    .map(lineOf)
    .sort((a, b) => a - b)
    .map((l) => [Math.max(0, l - context), Math.min(lines.length, l + context + 1)] as [number, number]);
  const merged: [number, number][] = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
    else merged.push(r);
  }
  return merged.map(([a, b]) => `// lines ${a + 1}-${b}\n${lines.slice(a, b).join("\n")}`).join("\n// …\n");
}

function charExcerpt(content: string, positions: number[], context = 800): string {
  return positions
    .sort((a, b) => a - b)
    .map((p) => `// chars ${Math.max(0, p - context)}-${p + context}\n${content.slice(Math.max(0, p - context), p + context)}`)
    .join("\n// …\n");
}

/** Finds every copy of the vulnerable code shipped in the package (source, CJS/ESM bundles, minified builds). */
export async function locateTargets(pkgDir: string, removed: string[]): Promise<TargetFile[]> {
  const anchors = anchorsFor(removed);
  const targets: TargetFile[] = [];
  for (const file of await listCode(pkgDir)) {
    const content = await readFile(path.join(pkgDir, file), "utf8");
    const positions = new Set<number>();
    for (const a of anchors) {
      const i = content.indexOf(a);
      if (i !== -1) positions.add(i);
    }
    if (positions.size === 0) continue;
    const longLines = content.split("\n").some((l) => l.length > 2000);
    targets.push({
      file,
      matches: positions.size,
      excerpt: longLines ? charExcerpt(content, [...positions]) : lineExcerpt(content, [...positions]),
    });
  }
  return targets.sort((a, b) => b.matches - a.matches);
}
