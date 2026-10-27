import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import path from "node:path";

/**
 * An append-only JSON Lines record of one run: every command with its exit
 * code and output tail, every model call with what was asked and what came
 * back, the scope check and the results. Nothing is written until a log is
 * started, so library use and tests are unaffected.
 */
let file: string | undefined;
let run: string | undefined;

export function startAudit(target: string, meta: Record<string, unknown>): string {
  mkdirSync(path.dirname(target), { recursive: true });
  file = target;
  run = new Date().toISOString();
  auditEvent("start", meta);
  return target;
}

export function stopAudit(summary: Record<string, unknown> = {}): void {
  auditEvent("end", summary);
  file = undefined;
  run = undefined;
}

export function auditing(): boolean {
  return file !== undefined;
}

export function auditEvent(type: string, data: Record<string, unknown>): void {
  if (!file) return;
  appendFileSync(file, `${JSON.stringify({ time: new Date().toISOString(), run, type, ...data })}\n`, "utf8");
}

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** Default location: `.autofix-cve/audit/<command>-<timestamp>.jsonl` in the project. */
export function defaultAuditPath(projectDir: string, command: string, now = new Date()): string {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  return path.join(projectDir, ".autofix-cve", "audit", `${command}-${stamp}.jsonl`);
}
