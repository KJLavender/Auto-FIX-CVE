import { runFile } from "../fix/exec.js";

const REF = /github\.com\/([^/]+)\/([^/]+)\/(commit|pull)\/([0-9a-f]{7,40}|\d+)/i;
const MAX_DIFF = 80_000;
const TEST_PATH = /(^|\/)(tests?|__tests__|specs?)\/|\.(test|spec)\.[cm]?[jt]sx?$/i;

let cachedToken: Promise<string | undefined> | undefined;

/** GITHUB_TOKEN / GH_TOKEN, else whatever `gh` is logged in as; unauthenticated works but is rate-limited. */
function githubToken(): Promise<string | undefined> {
  cachedToken ??= (async () => {
    const env = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
    if (env) return env;
    const res = await runFile("gh", ["auth", "token"], process.cwd(), 10_000).catch(() => undefined);
    return res?.ok ? res.output.trim() : undefined;
  })();
  return cachedToken;
}

/** Downloads the unified diff behind a GitHub commit or pull request URL. */
export async function fetchFixDiff(url: string): Promise<string | undefined> {
  const m = url.match(REF);
  if (!m) return undefined;
  const [, owner, repo, kind, ref] = m;
  const api = `https://api.github.com/repos/${owner}/${repo}/${kind === "pull" ? "pulls" : "commits"}/${ref}`;
  const token = await githubToken();
  const headers: Record<string, string> = { accept: "application/vnd.github.diff", "user-agent": "autofix-cve" };
  if (token) headers.authorization = `Bearer ${token}`;

  for (const target of [api, `https://github.com/${owner}/${repo}/${kind}/${ref}.diff`]) {
    const res = await fetch(target, { headers: target === api ? headers : { "user-agent": "autofix-cve" } }).catch(() => undefined);
    if (!res?.ok) continue;
    const text = await res.text();
    if (text.includes("diff --git")) return text.length > MAX_DIFF ? text.slice(0, MAX_DIFF) + "\n…(truncated)" : text;
  }
  return undefined;
}

export interface SplitDiff {
  code: string;
  tests: string;
}

/** Separates library changes (to port) from test changes (to learn how to reproduce the bug). */
export function splitDiff(diff: string): SplitDiff {
  const code: string[] = [];
  const tests: string[] = [];
  for (const section of diff.split(/^(?=diff --git )/m)) {
    const file = section.match(/^diff --git a\/(\S+)/)?.[1];
    if (!file) continue;
    (TEST_PATH.test(file) ? tests : code).push(section);
  }
  return { code: code.join(""), tests: tests.join("") };
}

/** Lines the upstream fix removed: the anchors for finding the same code in the installed package. */
export function removedLines(diff: string): string[] {
  return diff
    .split(/\r?\n/)
    .filter((l) => l.startsWith("-") && !l.startsWith("---"))
    .map((l) => l.slice(1).trim())
    .filter((l) => l.length >= 12);
}
