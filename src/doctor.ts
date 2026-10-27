import { run } from "./fix/exec.js";

interface Tool {
  name: string;
  /** Command that prints a version when the tool is installed. */
  probe: string;
  /** What works only when the tool is present. */
  enables: string;
  /** Overrides the command, e.g. AUTOFIX_POETRY="uvx poetry". */
  env?: string;
}

const LLM_ENABLES = "fix (code repair, backports), scan --triage";

const tools = (): Tool[] => [
  ...(process.env.AUTOFIX_LLM?.toLowerCase() === "openai"
    ? []
    : [{ name: "LLM CLI", probe: `${process.env.AUTOFIX_LLM_BIN ?? "claude"} --version`, enables: LLM_ENABLES, env: "AUTOFIX_LLM_BIN" }]),
  { name: "npm", probe: "npm --version", enables: "fix for npm projects, backports" },
  { name: "pnpm", probe: `${process.env.AUTOFIX_PNPM ?? "pnpm"} --version`, enables: "fix for pnpm projects", env: "AUTOFIX_PNPM" },
  { name: "yarn", probe: `${process.env.AUTOFIX_YARN ?? "yarn"} --version`, enables: "fix for Yarn projects", env: "AUTOFIX_YARN" },
  { name: "uv", probe: "uv --version", enables: "fix for uv projects" },
  { name: "poetry", probe: `${process.env.AUTOFIX_POETRY ?? "poetry"} --version`, enables: "fix for Poetry projects", env: "AUTOFIX_POETRY" },
  { name: "pipenv", probe: `${process.env.AUTOFIX_PIPENV ?? "pipenv"} --version`, enables: "fix for Pipenv projects", env: "AUTOFIX_PIPENV" },
  { name: "go", probe: `${process.env.AUTOFIX_GO ?? "go"} version`, enables: "fix for Go modules", env: "AUTOFIX_GO" },
  { name: "cargo", probe: `${process.env.AUTOFIX_CARGO ?? "cargo"} --version`, enables: "fix for Rust crates", env: "AUTOFIX_CARGO" },
  { name: "dotnet", probe: `${process.env.AUTOFIX_DOTNET ?? "dotnet"} --version`, enables: "fix for .NET (NuGet) projects", env: "AUTOFIX_DOTNET" },
  { name: "git", probe: "git --version", enables: "dirty-tree check, --pr" },
  { name: "gh", probe: "gh auth status", enables: "--pr on GitHub (must be logged in), faster fix-commit downloads for backports" },
];

export interface ToolStatus {
  name: string;
  ok: boolean;
  detail: string;
  enables: string;
  env?: string;
}

/** With AUTOFIX_LLM=openai: whether the endpoint answers `GET /models` with the configured key. */
async function checkOpenAi(): Promise<ToolStatus> {
  const base = (process.env.AUTOFIX_OPENAI_BASE_URL ?? "").replace(/\/+$/, "");
  const key = process.env.AUTOFIX_OPENAI_API_KEY;
  const status = { name: "LLM API", enables: LLM_ENABLES, env: "AUTOFIX_OPENAI_BASE_URL" };
  if (!base) return { ...status, ok: false, detail: "AUTOFIX_OPENAI_BASE_URL is not set" };
  if (!process.env.AUTOFIX_MODEL) return { ...status, ok: false, detail: "AUTOFIX_MODEL is not set" };
  const res = await fetch(`${base}/models`, { headers: key ? { authorization: `Bearer ${key}` } : {}, signal: AbortSignal.timeout(15_000) }).catch(
    (e: Error) => e,
  );
  if (res instanceof Error) return { ...status, ok: false, detail: res.message };
  return { ...status, ok: res.ok, detail: res.ok ? `${base} (${process.env.AUTOFIX_MODEL})` : `${base} answered ${res.status}` };
}

/** Probes every external tool. `scan` itself needs none of them, only network access to OSV. */
export async function checkTools(): Promise<ToolStatus[]> {
  const openai = process.env.AUTOFIX_LLM?.toLowerCase() === "openai" ? [checkOpenAi()] : [];
  return Promise.all([
    ...openai,
    ...tools().map(async (t) => {
      const res = await run(t.probe, process.cwd(), 30_000, { trusted: true });
      const first = res.output.trim().split(/\r?\n/).find((l) => l.trim()) ?? "";
      return { name: t.name, ok: res.ok, detail: res.ok ? first.trim().slice(0, 60) : "not found", enables: t.enables, env: t.env };
    }),
  ]);
}
