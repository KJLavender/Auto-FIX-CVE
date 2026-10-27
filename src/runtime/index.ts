import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import pc from "picocolors";
import semver from "semver";
import { loadKev, markExploited } from "../kev.js";
import { maxSeverity, type FailOn } from "../scan.js";
import { parseDockerfile } from "./dockerfile.js";
import { RUNTIME_SOURCES, type RuntimeStatus } from "./sources.js";

export interface RuntimeEdit {
  line: number;
  from: string;
  to: string;
}

export interface RuntimeFinding {
  /** Dockerfile path relative to the scanned directory, with forward slashes. */
  file: string;
  line: number;
  /** The FROM image as written. */
  image: string;
  stage?: string;
  /** Part of the image that ships (the last stage or one it builds on), not just a build stage. */
  shipped: boolean;
  status: RuntimeStatus;
  /** Days until end of support; negative once it has passed. */
  eolDays?: number;
  /** The line edit that pins the newest release, when one is needed and can be made automatically. */
  edit?: RuntimeEdit;
  /** Why no automatic edit is offered although one is needed. */
  manual?: string;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "bin", "obj", "target", "vendor", ".venv", "venv", "__pycache__"]);
const DOCKERFILE = /^(Dockerfile|Containerfile)(\..+)?$|\.(Dockerfile|Containerfile)$/i;

async function findDockerfiles(root: string, dir = root, depth = 0, out: string[] = []): Promise<string[]> {
  if (depth > 6) return out;
  for (const entry of await readdir(dir, { withFileTypes: true }).catch(() => [])) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) await findDockerfiles(root, path.join(dir, entry.name), depth + 1, out);
    } else if (DOCKERFILE.test(entry.name)) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

const DAY = 86_400_000;

/** Checks the Node.js and .NET runtimes that the Dockerfiles under `root` build on. */
export async function scanRuntimes(root: string, today = new Date()): Promise<RuntimeFinding[]> {
  const kev = loadKev();
  const findings: RuntimeFinding[] = [];
  for (const file of (await findDockerfiles(root)).sort()) {
    const text = await readFile(file, "utf8");
    const lines = text.split(/\r?\n/);
    for (const from of parseDockerfile(text)) {
      const source = RUNTIME_SOURCES.find((s) => s.matches(from.repository));
      const status = source && (await source.check(from.repository, from.tag));
      if (!status) continue;
      markExploited(status.vulns, await kev);
      const needed = !status.version || status.vulns.length > 0;
      const finding: RuntimeFinding = {
        file: path.relative(root, file).split(path.sep).join("/"),
        line: from.line,
        image: from.raw,
        stage: from.stage,
        shipped: from.final,
        status,
        eolDays: status.eol ? Math.ceil((Date.parse(status.eol) - today.getTime()) / DAY) : undefined,
      };
      const target = status.pinnedTag;
      if (needed && target && target !== from.tag) {
        if (from.arg && from.tag?.startsWith(from.arg.value) && from.arg.value) {
          // FROM node:${NODE_VERSION}-slim: change the ARG default rather than the FROM line.
          const rest = from.tag.slice(from.arg.value.length);
          const old = lines[from.arg.line - 1];
          if (target.endsWith(rest)) {
            const value = target.slice(0, target.length - rest.length);
            finding.edit = { line: from.arg.line, from: old, to: old.replace(`=${from.arg.value}`, `=${value}`) };
          }
        } else if (!/\$/.test(from.raw)) {
          const old = lines[from.line - 1];
          const ref = from.raw.split("@")[0];
          const newRef = from.tag ? `${ref.slice(0, ref.length - from.tag.length)}${target}` : `${ref}:${target}`;
          finding.edit = { line: from.line, from: old, to: old.replace(from.raw, newRef) };
        }
        if (!finding.edit) finding.manual = "the tag is built from build arguments; set it by hand";
        else if (from.digest) finding.manual = "the @sha256 digest was dropped; pin the new image's digest after pulling it";
      }
      findings.push(finding);
    }
  }
  return findings;
}

/** Whether a runtime finding fails `runtime --fail-on <level>`. Only images that ship count. */
export function runtimeFails(f: RuntimeFinding, failOn: FailOn): boolean {
  if (!f.shipped || failOn === "none") return false;
  if (failOn === "any" || failOn === "likely") return f.status.vulns.length > 0 || (f.eolDays !== undefined && f.eolDays < 0);
  // The runtime runs every request, so nothing is unreachable; and release notes rarely rate
  // their CVEs, so an unrated one counts as serious rather than being waved through.
  return f.status.vulns.some((v) => v.knownExploited || maxSeverity([v]) === 0 || maxSeverity([v]) >= 3);
}

/** Writes the pinning edits; returns the files changed. */
export async function applyRuntimeEdits(root: string, findings: RuntimeFinding[]): Promise<string[]> {
  const byFile = new Map<string, RuntimeEdit[]>();
  for (const f of findings) if (f.edit) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f.edit]);
  for (const [file, edits] of byFile) {
    const full = path.join(root, file);
    const text = await readFile(full, "utf8");
    const eol = text.includes("\r\n") ? "\r\n" : "\n";
    const lines = text.split(/\r?\n/);
    for (const e of edits) if (lines[e.line - 1] === e.from) lines[e.line - 1] = e.to;
    await writeFile(full, lines.join(eol), "utf8");
  }
  return [...byFile.keys()];
}

export function formatRuntimeReport(findings: RuntimeFinding[], maxVulns = 8): string {
  if (!findings.length) return pc.dim("No Node.js or .NET base images found in Dockerfiles.");
  const out: string[] = [];
  for (const f of findings) {
    const s = f.status;
    const where = `${f.file}:${f.line}`;
    const what = s.version ? `${s.runtime} ${s.version}` : `${s.runtime} ${s.line}.x, floating (whatever version the registry or its cache serves)`;
    const stage = f.shipped ? "" : pc.dim(`  build stage${f.stage ? ` ${f.stage}` : ""}, not shipped`);
    out.push(`${pc.bold(where)}  ${f.image}  ${what}${stage}`);
    if (f.eolDays !== undefined && f.eolDays <= 90) {
      const text = f.eolDays < 0 ? `support ENDED on ${s.eol}` : `support ends ${s.eol} (in ${f.eolDays} days)`;
      out.push(`  ${pc.red(text)}: move to a newer ${s.runtime} line`);
    }
    // Known exploited first, then what only the newest release fixes (this week's news, usually
    // unrated yet), then by severity; other unrated ones sit just below high.
    const rank = (v: (typeof s.vulns)[number]) =>
      v.knownExploited ? 10 : s.latest && v.fixedVersions.includes(s.latest) ? 5 : maxSeverity([v]) || 2.5;
    // Ties: most recently fixed first, i.e. the newest news.
    const fixedIn = (v: (typeof s.vulns)[number]) => semver.coerce(v.fixedVersions[0])?.version ?? "0.0.0";
    const shown = [...s.vulns].sort((a, b) => rank(b) - rank(a) || semver.compare(fixedIn(b), fixedIn(a))).slice(0, maxVulns);
    for (const v of shown) {
      const cves = v.aliases.filter((a) => a.startsWith("CVE-") && a !== v.id);
      const kev = v.knownExploited ? ` ${pc.bgRed(pc.white(" KNOWN EXPLOITED "))}` : "";
      const sev = v.severity ? `[${v.severity}]` : "[UNRATED]";
      out.push(`  ${sev}${kev} ${v.id}${cves.length ? ` (${cves.join(", ")})` : ""}  ${v.summary}`);
    }
    if (s.vulns.length > shown.length) out.push(pc.dim(`  … ${s.vulns.length - shown.length} more, all fixed by the pin below`));
    if (f.edit) out.push(`  ${pc.green("→ pin")} ${f.edit.to.trim()}  ${pc.dim(`(newest ${s.line}.x: ${s.latest}, ${s.latestDate})`)}`);
    if (f.manual) out.push(`  ${pc.yellow("note:")} ${f.manual}`);
    if (!f.edit && !f.manual && !s.vulns.length) out.push(`  ${pc.green("no known vulnerabilities")}`);
    out.push("");
  }
  return out.join("\n");
}
