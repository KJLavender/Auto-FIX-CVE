import { spawn } from "node:child_process";

export interface CommandResult {
  ok: boolean;
  output: string;
}

/** Runs a shell command, capturing stdout and stderr together. */
export function run(command: string, cwd: string, timeoutMs = 10 * 60_000): Promise<CommandResult> {
  return exec(command, [], { cwd, shell: true }, timeoutMs);
}

/** Runs an executable directly, without a shell, so arguments need no quoting. */
export function runFile(file: string, args: string[], cwd: string, timeoutMs = 60_000): Promise<CommandResult> {
  return exec(file, args, { cwd, shell: false }, timeoutMs);
}

function exec(
  file: string,
  args: string[],
  opts: { cwd: string; shell: boolean },
  timeoutMs: number,
): Promise<CommandResult> {
  return new Promise((resolve) => {
    // No stdin and CI-style env: a command that would prompt ("Ok to proceed? (y)")
    // fails fast instead of hanging the run.
    const child = spawn(file, args, {
      ...opts,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1", CI: "1", npm_config_yes: "false" },
    });
    let output = "";
    const append = (d: Buffer) => (output += d.toString("utf8"));
    child.stdout.on("data", append);
    child.stderr.on("data", append);
    const timer = setTimeout(() => {
      output += `\n[autofix-cve] command timed out after ${timeoutMs / 1000}s`;
      child.kill();
    }, timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ ok: false, output: `${output}\n${e.message}` });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, output });
    });
  });
}

/** Keeps the end of long output, where test runners and compilers put the summary. */
export function tail(text: string, max = 8000): string {
  return text.length <= max ? text : `…(truncated)…\n${text.slice(-max)}`;
}
