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

const TOOLS: Tool[] = [
  { name: "LLM CLI", probe: `${process.env.AUTOFIX_LLM_BIN ?? "claude"} --version`, enables: "fix (code repair, backports), scan --triage", env: "AUTOFIX_LLM_BIN" },
  { name: "npm", probe: "npm --version", enables: "fix for npm projects, backports" },
  { name: "pnpm", probe: `${process.env.AUTOFIX_PNPM ?? "pnpm"} --version`, enables: "fix for pnpm projects", env: "AUTOFIX_PNPM" },
  { name: "yarn", probe: `${process.env.AUTOFIX_YARN ?? "yarn"} --version`, enables: "fix for Yarn projects", env: "AUTOFIX_YARN" },
  { name: "uv", probe: "uv --version", enables: "fix for uv projects" },
  { name: "poetry", probe: `${process.env.AUTOFIX_POETRY ?? "poetry"} --version`, enables: "fix for Poetry projects", env: "AUTOFIX_POETRY" },
  { name: "pipenv", probe: `${process.env.AUTOFIX_PIPENV ?? "pipenv"} --version`, enables: "fix for Pipenv projects", env: "AUTOFIX_PIPENV" },
  { name: "go", probe: `${process.env.AUTOFIX_GO ?? "go"} version`, enables: "fix for Go modules", env: "AUTOFIX_GO" },
  { name: "cargo", probe: `${process.env.AUTOFIX_CARGO ?? "cargo"} --version`, enables: "fix for Rust crates", env: "AUTOFIX_CARGO" },
  { name: "git", probe: "git --version", enables: "dirty-tree check, --pr" },
  { name: "gh", probe: "gh auth status", enables: "--pr (must be logged in), faster fix-commit downloads for backports" },
];

export interface ToolStatus {
  name: string;
  ok: boolean;
  detail: string;
  enables: string;
  env?: string;
}

/** Probes every external tool. `scan` itself needs none of them, only network access to OSV. */
export async function checkTools(): Promise<ToolStatus[]> {
  return Promise.all(
    TOOLS.map(async (t) => {
      const res = await run(t.probe, process.cwd(), 30_000);
      const first = res.output.trim().split(/\r?\n/).find((l) => l.trim()) ?? "";
      return { name: t.name, ok: res.ok, detail: res.ok ? first.trim().slice(0, 60) : "not found", enables: t.enables, env: t.env };
    }),
  );
}
