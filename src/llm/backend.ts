import { spawn } from "node:child_process";

export interface CompletionRequest {
  system: string;
  prompt: string;
  /** JSON Schema the response must satisfy. */
  schema: object;
}

export interface CompletionResult<T> {
  output: T;
  costUsd: number;
}

export interface LlmBackend {
  complete<T>(req: CompletionRequest): Promise<CompletionResult<T>>;
}

export const DEFAULT_MODEL = process.env.AUTOFIX_MODEL ?? "claude-sonnet-5-5";

interface CliResponse {
  is_error?: boolean;
  result?: string;
  structured_output?: unknown;
  total_cost_usd?: number;
}

/**
 * Uses the locally installed Claude Code CLI in headless mode, so calls run on
 * the user's Claude subscription and no API key is needed.
 */
export class ClaudeCliBackend implements LlmBackend {
  constructor(
    private readonly model = DEFAULT_MODEL,
    private readonly effort = process.env.AUTOFIX_EFFORT ?? "medium",
    private readonly executable = process.env.AUTOFIX_CLAUDE_BIN ?? "claude",
  ) {}

  async complete<T>(req: CompletionRequest): Promise<CompletionResult<T>> {
    const args = [
      "-p",
      "--output-format", "json",
      "--model", this.model,
      "--effort", this.effort,
      "--system-prompt", req.system,
      "--json-schema", JSON.stringify(req.schema),
      // A plain completion: no tools, no user CLAUDE.md, no saved session.
      "--tools", "",
      "--setting-sources", "",
      "--no-session-persistence",
    ];
    const stdout = await new Promise<string>((resolve, reject) => {
      const child = spawn(this.executable, args, { stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      let err = "";
      child.stdout.setEncoding("utf8").on("data", (d: string) => (out += d));
      child.stderr.setEncoding("utf8").on("data", (d: string) => (err += d));
      child.on("error", (e) => reject(new Error(`Could not start '${this.executable}': ${e.message}`)));
      child.on("close", (code) => {
        if (code === 0) resolve(out);
        else reject(new Error(`claude exited with ${code}: ${(err || out).slice(0, 2000)}`));
      });
      child.stdin.end(req.prompt, "utf8");
    });

    const res = JSON.parse(stdout) as CliResponse;
    if (res.is_error || res.structured_output === undefined) {
      throw new Error(`claude returned no structured output: ${res.result ?? stdout.slice(0, 2000)}`);
    }
    return { output: res.structured_output as T, costUsd: res.total_cost_usd ?? 0 };
  }
}
