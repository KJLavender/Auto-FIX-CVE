import { spawn } from "node:child_process";
import { auditEvent } from "../audit.js";

export interface CommandResult {
  ok: boolean;
  output: string;
}

export interface RunOptions {
  /**
   * Tools of our own (git, gh) that need the caller's credentials. Everything
   * else, installs, checks and anything that runs package code, gets only the
   * environment a build needs: a freshly upgraded package's install script
   * must not be able to read GITHUB_TOKEN or an API key.
   */
  trusted?: boolean;
}

// Variables a package manager, compiler or test runner needs; matched by name or prefix.
const PASS_NAMES = new Set(
  [
    "PATH", "PATHEXT", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "OS", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
    "TEMP", "TMP", "TMPDIR", "USER", "USERNAME", "LOGNAME", "SHELL", "TERM", "LANG", "TZ",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "VIRTUAL_ENV", "JAVA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
  ].map((n) => n.toUpperCase()),
);
const PASS_PREFIXES = ["LC_", "NPM_CONFIG_", "YARN_", "PNPM_", "COREPACK_", "NVM_", "UV_", "PIP_", "POETRY_", "PIPENV_", "PYENV",
  "CARGO_", "RUSTUP_", "GO", "DOTNET_", "NUGET_", "MSBUILD"];
// Even within those prefixes, credentials stay out unless the user names them.
const SECRET = /TOKEN|AUTH|PASSWORD|PASSWD|SECRET|_KEY$|APIKEY|CREDENTIAL/i;

/**
 * The environment for project commands: the allow-list above, plus anything
 * named in AUTOFIX_PASS_ENV (e.g. `NPM_TOKEN` for a private registry), plus
 * CI-style settings so nothing waits for input.
 */
export function projectEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const extra = new Set((source.AUTOFIX_PASS_ENV ?? "").split(",").map((s) => s.trim().toUpperCase()).filter(Boolean));
  const env: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(source)) {
    const key = name.toUpperCase();
    const allowed = PASS_NAMES.has(key) || (PASS_PREFIXES.some((p) => key.startsWith(p)) && !SECRET.test(key));
    if (allowed || extra.has(key)) env[name] = value;
  }
  if (source.AUTOFIX_IGNORE_SCRIPTS === "1") {
    // Lifecycle scripts of installed packages do not run (npm, pnpm, Yarn classic and Berry).
    env.npm_config_ignore_scripts = "true";
    env.YARN_ENABLE_SCRIPTS = "false";
  }
  return { ...env, FORCE_COLOR: "0", NO_COLOR: "1", CI: "1", npm_config_yes: "false" };
}

/** Splits a wrapper template into arguments, honouring "double" and 'single' quotes. */
export function splitArgs(template: string): string[] {
  return [...template.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map((m) => m[1] ?? m[2] ?? m[3]);
}

/**
 * AUTOFIX_EXEC_WRAPPER runs project commands inside a sandbox: the template's
 * words become the program and its arguments, `{dir}` is the project
 * directory, and the command is appended as one final argument. For example
 * `docker run --rm --network none -v {dir}:/work -w /work node:22 sh -c`.
 */
export function wrapCommand(command: string, cwd: string, wrapper = process.env.AUTOFIX_EXEC_WRAPPER): { file: string; args: string[]; shell: boolean } {
  if (!wrapper?.trim()) return { file: command, args: [], shell: true };
  const [file, ...args] = splitArgs(wrapper).map((a) => a.replaceAll("{dir}", cwd));
  return { file, args: [...args, command], shell: false };
}

/** Runs a shell command, capturing stdout and stderr together. Project commands go through the sandbox wrapper, if any. */
export function run(command: string, cwd: string, timeoutMs = 10 * 60_000, opts: RunOptions = {}): Promise<CommandResult> {
  if (opts.trusted) return exec(command, [], { cwd, shell: true, env: trustedEnv() }, timeoutMs, command);
  const { file, args, shell } = wrapCommand(command, cwd);
  return exec(file, args, { cwd, shell, env: projectEnv() }, timeoutMs, command);
}

/** Runs an executable directly, without a shell, so arguments need no quoting. */
export function runFile(file: string, args: string[], cwd: string, timeoutMs = 60_000, opts: RunOptions = {}): Promise<CommandResult> {
  // Inline scripts (`node -e …`) are logged by size, not in full.
  const label = [file, ...args.map((a) => (a.length > 120 ? `<${a.length} chars>` : a))].join(" ");
  return exec(file, args, { cwd, shell: false, env: opts.trusted ? trustedEnv() : projectEnv() }, timeoutMs, label);
}

function trustedEnv(): NodeJS.ProcessEnv {
  return { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1", CI: "1", npm_config_yes: "false" };
}

function exec(
  file: string,
  args: string[],
  opts: { cwd: string; shell: boolean; env: NodeJS.ProcessEnv },
  timeoutMs: number,
  label: string,
): Promise<CommandResult> {
  const started = Date.now();
  return new Promise((resolve) => {
    const done = (result: CommandResult, code: number | null) => {
      auditEvent("command", { command: label, cwd: opts.cwd, exitCode: code, ok: result.ok, ms: Date.now() - started, output: result.output.slice(-2000) });
      resolve(result);
    };
    // No stdin: a command that would prompt ("Ok to proceed? (y)") fails fast instead of hanging the run.
    const child = spawn(file, args, { cwd: opts.cwd, shell: opts.shell, env: opts.env, stdio: ["ignore", "pipe", "pipe"] });
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
      done({ ok: false, output: `${output}\n${e.message}` }, null);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      done({ ok: code === 0, output }, code);
    });
  });
}

/** Keeps the end of long output, where test runners and compilers put the summary. */
export function tail(text: string, max = 8000): string {
  return text.length <= max ? text : `…(truncated)…\n${text.slice(-max)}`;
}
