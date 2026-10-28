import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { auditEvent } from "./audit.js";
import type { Ecosystem } from "./versions.js";

/**
 * What one run learned about one package: a verified fix (and how the code
 * was adapted), or an attempt that failed (and why). Only outcomes the tool
 * itself established are recorded, never the model's free-form notes, so the
 * memory is as trustworthy as the checks that produced it.
 */
export interface Lesson {
  ecosystem: Ecosystem;
  package: string;
  from: string;
  to?: string;
  kind: "upgrade" | "override" | "backport" | "mitigate";
  outcome: "fixed" | "failed";
  /** How the code was changed (fixed), or what was tried (failed). */
  summary: string;
  /** For failures: why it was rolled back, e.g. the failing command and its error. */
  failure?: string;
  /** Source files the fix edited, besides manifests and lockfiles. */
  files: string[];
  date: string;
}

export interface LessonQuery {
  ecosystem: Ecosystem;
  package: string;
  from: string;
  to?: string;
  kind?: Lesson["kind"];
}

/** Where lessons live. The default is a file in the repository; anything else (a shared service) can implement this. */
export interface MemoryStore {
  recall(query: LessonQuery, limit?: number): Promise<Lesson[]>;
  record(lesson: Lesson): Promise<void>;
}

const MAX_PER_PACKAGE = 20;
const MAX_TOTAL = 500;

const samePackage = (eco: Ecosystem, a: string, b: string) => (eco === "NuGet" ? a.toLowerCase() === b.toLowerCase() : a === b);
const major = (v: string | undefined) => /^v?(\d+)/.exec(v ?? "")?.[1];

/**
 * Lessons in a JSON file, by default `.autofix-cve/memory.json` in the project,
 * so they are reviewed and shared through git like any other change, and a
 * CI runner that starts empty still has them. `AUTOFIX_MEMORY` points
 * several repositories at one file.
 */
export class FileMemory implements MemoryStore {
  constructor(readonly file: string) {}

  static forProject(projectDir: string): FileMemory {
    return new FileMemory(path.resolve(process.env.AUTOFIX_MEMORY || path.join(projectDir, ".autofix-cve", "memory.json")));
  }

  private async load(): Promise<Lesson[]> {
    if (!existsSync(this.file)) return [];
    try {
      const doc = JSON.parse(await readFile(this.file, "utf8")) as { lessons?: Lesson[] };
      return doc.lessons ?? [];
    } catch {
      return [];
    }
  }

  /** The most useful lessons first: same kind of fix, same target major, same starting major; successes, then newest. */
  async recall(q: LessonQuery, limit = 5): Promise<Lesson[]> {
    const score = (l: Lesson) =>
      (q.kind && l.kind === q.kind ? 4 : 0) + (q.to && major(l.to) === major(q.to) ? 2 : 0) + (major(l.from) === major(q.from) ? 1 : 0);
    const found = (await this.load())
      .filter((l) => l.ecosystem === q.ecosystem && samePackage(q.ecosystem, l.package, q.package))
      // Equally relevant: what worked before what failed, then newest.
      .sort((a, b) => score(b) - score(a) || Number(b.outcome === "fixed") - Number(a.outcome === "fixed") || b.date.localeCompare(a.date))
      .slice(0, limit);
    auditEvent("memory", { action: "recall", package: q.package, from: q.from, to: q.to, lessons: found.length });
    return found;
  }

  async record(lesson: Lesson): Promise<void> {
    const same = (l: Lesson) =>
      l.ecosystem === lesson.ecosystem && samePackage(l.ecosystem, l.package, lesson.package) && l.from === lesson.from &&
      l.to === lesson.to && l.kind === lesson.kind && l.outcome === lesson.outcome;
    // A repeat of the same attempt replaces the older note instead of piling up.
    let lessons = [...(await this.load()).filter((l) => !same(l)), lesson];
    const forPackage = lessons.filter((l) => samePackage(l.ecosystem, l.package, lesson.package) && l.ecosystem === lesson.ecosystem);
    if (forPackage.length > MAX_PER_PACKAGE) {
      const drop = new Set(forPackage.sort((a, b) => a.date.localeCompare(b.date)).slice(0, forPackage.length - MAX_PER_PACKAGE));
      lessons = lessons.filter((l) => !drop.has(l));
    }
    lessons = lessons.sort((a, b) => a.date.localeCompare(b.date)).slice(-MAX_TOTAL);
    await mkdir(path.dirname(this.file), { recursive: true });
    await writeFile(this.file, `${JSON.stringify({ version: 1, lessons }, null, 2)}\n`, "utf8");
    auditEvent("memory", { action: "record", package: lesson.package, from: lesson.from, to: lesson.to, outcome: lesson.outcome });
  }
}

/** The prompt section with earlier lessons, or nothing when there are none. */
export function formatLessons(pkg: string, lessons: Lesson[]): string {
  if (!lessons.length) return "";
  const lines = lessons.map((l) => {
    const step = `${l.date}, ${l.kind} ${l.from}${l.to ? ` → ${l.to}` : ""}`;
    const files = l.files.length ? ` (changed ${l.files.join(", ")})` : "";
    return l.outcome === "fixed"
      ? `- ${step}: WORKED. ${l.summary}${files}`
      : `- ${step}: FAILED and was rolled back. Tried: ${l.summary}. Why: ${l.failure ?? "unknown"}`;
  });
  return `\n## What earlier runs in this repository learned about ${pkg}\nThese outcomes were verified by the project's checks. Reuse approaches that worked; do not repeat ones that failed.\n${lines.join("\n")}`;
}

const MANIFEST = /(^|\/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|pyproject\.toml|uv\.lock|poetry\.lock|Pipfile(\.lock)?|go\.(mod|sum)|Cargo\.(toml|lock)|.*\.(cs|fs|vb)proj|Directory\.Packages\.props|packages\.lock\.json|\.autofix-cve(\.json|\/.*))$/;

/** Turns a fix or mitigation result into a lesson; undefined when there is nothing to learn (a skip). */
export function lessonFrom(
  dep: { ecosystem: Ecosystem; name: string; version: string },
  r: { status: string; strategy?: string; to?: string; reason?: string; explanations?: string[]; explanation?: string; changedFiles: string[] },
  kind?: Lesson["kind"],
  now = new Date(),
): Lesson | undefined {
  const outcome = r.status === "fixed" || r.status === "mitigated" ? "fixed" : r.status === "failed" ? "failed" : undefined;
  const lessonKind = kind ?? (r.strategy === "upgrade" || r.strategy === "override" || r.strategy === "backport" ? r.strategy : undefined);
  if (!outcome || !lessonKind) return undefined;
  const notes = [...(r.explanations ?? []), ...(r.explanation ? [r.explanation] : [])].filter(Boolean);
  const summary = notes.length ? notes.join(" Then: ") : outcome === "fixed" ? "no code changes were needed" : "no code changes were tried";
  return {
    ecosystem: dep.ecosystem,
    package: dep.name,
    from: dep.version,
    to: r.to,
    kind: lessonKind,
    outcome,
    summary: summary.slice(0, 1500),
    ...(outcome === "failed" ? { failure: (r.reason ?? "unknown").slice(0, 800) } : {}),
    files: r.changedFiles.filter((f) => !MANIFEST.test(f)),
    date: now.toISOString().slice(0, 10),
  };
}
