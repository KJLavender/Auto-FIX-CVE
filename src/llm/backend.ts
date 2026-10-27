import { spawn } from "node:child_process";
import { auditEvent, sha256 } from "../audit.js";
import { fetchWithRetry } from "../http.js";

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

export class BudgetExceededError extends Error {}

/**
 * Stops calling the model once the spend reaches `limitUsd`. A call that is
 * refused throws, so the fix in progress fails and rolls back like any other
 * failure instead of continuing half-done.
 */
export class BudgetBackend implements LlmBackend {
  spentUsd = 0;
  constructor(
    private readonly inner: LlmBackend,
    private readonly limitUsd: number,
  ) {}

  async complete<T>(req: CompletionRequest): Promise<CompletionResult<T>> {
    if (this.spentUsd >= this.limitUsd) {
      throw new BudgetExceededError(`model budget of $${this.limitUsd.toFixed(2)} reached ($${this.spentUsd.toFixed(4)} spent)`);
    }
    const res = await this.inner.complete<T>(req);
    this.spentUsd += res.costUsd;
    return res;
  }
}

export const DEFAULT_MODEL = process.env.AUTOFIX_MODEL ?? "claude-sonnet-5-5";

interface CliResponse {
  is_error?: boolean;
  result?: string;
  structured_output?: unknown;
  total_cost_usd?: number;
}

/**
 * Uses a locally installed LLM CLI in headless mode, so calls run on the
 * user's existing subscription and no API key is needed.
 */
export class CliBackend implements LlmBackend {
  constructor(
    private readonly model = DEFAULT_MODEL,
    private readonly effort = process.env.AUTOFIX_EFFORT ?? "medium",
    private readonly executable = process.env.AUTOFIX_LLM_BIN ?? "claude",
  ) {}

  async complete<T>(req: CompletionRequest): Promise<CompletionResult<T>> {
    const args = [
      "-p",
      "--output-format", "json",
      "--model", this.model,
      "--effort", this.effort,
      "--system-prompt", req.system,
      "--json-schema", JSON.stringify(req.schema),
      // A plain completion: no tools, no user settings or memory files, no saved session.
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
        else reject(new Error(`${this.executable} exited with ${code}: ${(err || out).slice(0, 2000)}`));
      });
      child.stdin.end(req.prompt, "utf8");
    });

    const res = JSON.parse(stdout) as CliResponse;
    if (res.is_error || res.structured_output === undefined) {
      throw new Error(`${this.executable} returned no structured output: ${res.result ?? stdout.slice(0, 2000)}`);
    }
    return { output: res.structured_output as T, costUsd: res.total_cost_usd ?? 0 };
  }
}

interface ChatResponse {
  choices?: { message?: { content?: string | null } }[];
  usage?: { prompt_tokens?: number; completion_tokens?: number };
  error?: { message?: string };
}

/** The first JSON object in a reply, tolerating Markdown fences and text around it. */
export function extractJson(text: string): unknown {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(text);
  const body = (fenced ? fenced[1] : text).trim();
  try {
    return JSON.parse(body);
  } catch {
    const start = body.indexOf("{");
    const end = body.lastIndexOf("}");
    if (start >= 0 && end > start) return JSON.parse(body.slice(start, end + 1));
    throw new Error("the reply contains no JSON object");
  }
}

function missingKeys(output: unknown, schema: object): string[] {
  const required = (schema as { required?: string[] }).required ?? [];
  if (!output || typeof output !== "object" || Array.isArray(output)) return ["(not an object)"];
  return required.filter((k) => !(k in output));
}

/**
 * Any OpenAI-compatible chat completions endpoint: a company LLM gateway,
 * Azure OpenAI behind a proxy, vLLM, Ollama… Structured output is requested
 * with `response_format` (switchable, since gateways differ in support), and a
 * reply that is not valid JSON gets one corrective retry.
 */
export class OpenAiBackend implements LlmBackend {
  constructor(
    private readonly baseUrl = process.env.AUTOFIX_OPENAI_BASE_URL ?? "",
    private readonly apiKey = process.env.AUTOFIX_OPENAI_API_KEY ?? "",
    private readonly model = process.env.AUTOFIX_MODEL ?? "",
    private readonly jsonMode = (process.env.AUTOFIX_OPENAI_JSON ?? "json_schema") as "json_schema" | "json_object" | "none",
    /** USD per million input / output tokens, so --max-cost works; 0 when unknown. */
    private readonly price = {
      input: Number(process.env.AUTOFIX_PRICE_INPUT ?? 0),
      output: Number(process.env.AUTOFIX_PRICE_OUTPUT ?? 0),
    },
  ) {}

  async complete<T>(req: CompletionRequest): Promise<CompletionResult<T>> {
    if (!this.baseUrl) throw new Error("AUTOFIX_LLM=openai needs AUTOFIX_OPENAI_BASE_URL (e.g. https://gateway.example.com/v1).");
    if (!this.model) throw new Error("AUTOFIX_LLM=openai needs AUTOFIX_MODEL set to a model the endpoint serves.");
    // Without native schema support, the schema goes into the instructions instead.
    const system =
      this.jsonMode === "json_schema"
        ? req.system
        : `${req.system}\n\nReply with only a JSON object that matches this JSON Schema:\n${JSON.stringify(req.schema)}`;
    const messages: { role: string; content: string }[] = [
      { role: "system", content: system },
      { role: "user", content: req.prompt },
    ];
    let costUsd = 0;
    for (let attempt = 1; ; attempt++) {
      const reply = await this.chat(messages, req.schema);
      costUsd += reply.cost;
      try {
        const output = extractJson(reply.content);
        const missing = missingKeys(output, req.schema);
        if (missing.length) throw new Error(`missing required fields: ${missing.join(", ")}`);
        return { output: output as T, costUsd };
      } catch (e) {
        if (attempt >= 2) throw new Error(`${this.model} did not return valid JSON: ${(e as Error).message}\n${reply.content.slice(0, 1000)}`);
        messages.push(
          { role: "assistant", content: reply.content },
          { role: "user", content: `That reply was not usable (${(e as Error).message}). Reply again with only the JSON object.` },
        );
      }
    }
  }

  private async chat(messages: { role: string; content: string }[], schema: object): Promise<{ content: string; cost: number }> {
    const responseFormat =
      this.jsonMode === "json_schema"
        ? { response_format: { type: "json_schema", json_schema: { name: "result", schema } } }
        : this.jsonMode === "json_object"
          ? { response_format: { type: "json_object" } }
          : {};
    const res = await fetchWithRetry(`${this.baseUrl.replace(/\/+$/, "")}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {}) },
      body: JSON.stringify({ model: this.model, messages, ...responseFormat }),
      signal: AbortSignal.timeout(10 * 60_000),
    });
    const body = (await res.json().catch(() => ({}))) as ChatResponse;
    if (!res.ok) throw new Error(`LLM endpoint returned ${res.status}: ${body.error?.message ?? JSON.stringify(body).slice(0, 500)}`);
    const content = body.choices?.[0]?.message?.content ?? "";
    const cost =
      ((body.usage?.prompt_tokens ?? 0) * this.price.input + (body.usage?.completion_tokens ?? 0) * this.price.output) / 1_000_000;
    return { content, cost };
  }
}

/** The backend chosen by `AUTOFIX_LLM`: `cli` (default, the local CLI) or `openai` (an OpenAI-compatible endpoint). */
export function createBackend(): LlmBackend {
  const kind = (process.env.AUTOFIX_LLM ?? "cli").toLowerCase();
  if (kind === "openai") return new OpenAiBackend();
  if (kind !== "cli") throw new Error(`Unknown AUTOFIX_LLM '${kind}': use cli or openai.`);
  return new CliBackend();
}

/**
 * Records every model call in the audit log: a hash and the size of what was
 * sent (the prompt holds project source, so the hash proves what was asked
 * without copying the code), and the full reply, which is what got applied.
 */
export class AuditBackend implements LlmBackend {
  constructor(private readonly inner: LlmBackend) {}

  async complete<T>(req: CompletionRequest): Promise<CompletionResult<T>> {
    const sent = { model: DEFAULT_MODEL, systemSha256: sha256(req.system), promptSha256: sha256(req.prompt), promptChars: req.prompt.length };
    try {
      const res = await this.inner.complete<T>(req);
      auditEvent("model", { ...sent, ok: true, costUsd: res.costUsd, output: res.output });
      return res;
    } catch (e) {
      auditEvent("model", { ...sent, ok: false, error: (e as Error).message });
      throw e;
    }
  }
}
