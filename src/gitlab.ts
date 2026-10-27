import { fetchWithRetry } from "./http.js";

export interface GitlabProject {
  /** REST API root, e.g. `https://gitlab.example.com/api/v4`. */
  api: string;
  /** Namespace and project, e.g. `group/sub/project`. */
  path: string;
}

/**
 * Works out the GitLab project from an `origin` URL: https (with or without
 * credentials), scp-style `git@host:group/project.git` and `ssh://` forms.
 * `AUTOFIX_GITLAB_API`, or GitLab CI's own `CI_API_V4_URL`, overrides the API root.
 */
export function gitlabProject(remote: string): GitlabProject | undefined {
  const url = remote.trim();
  let host: string;
  let scheme = "https";
  let projectPath: string;
  const scp = /^[^@/\s]+@([^:/\s]+):(?!\d+\/)(.+)$/.exec(url);
  if (scp) {
    host = scp[1];
    projectPath = scp[2];
  } else {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return undefined;
    }
    if (parsed.protocol === "http:") scheme = "http";
    host = parsed.hostname + (parsed.protocol.startsWith("http") && parsed.port ? `:${parsed.port}` : "");
    projectPath = parsed.pathname.replace(/^\/+/, "");
  }
  projectPath = projectPath.replace(/\.git$/, "").replace(/\/+$/, "");
  if (!host || !projectPath.includes("/")) return undefined;
  const api = (process.env.AUTOFIX_GITLAB_API || process.env.CI_API_V4_URL || `${scheme}://${host}/api/v4`).replace(/\/+$/, "");
  return { api, path: projectPath };
}

/**
 * The token to send to `project`'s API. `AUTOFIX_GITLAB_TOKEN` is meant for this
 * tool and always used. The generic `GITLAB_TOKEN` often belongs to another
 * instance, so it is only sent to the host it is for: `GITLAB_HOST` when set
 * (as with the glab CLI), otherwise gitlab.com.
 */
export function gitlabToken(project: GitlabProject): string | undefined {
  if (process.env.AUTOFIX_GITLAB_TOKEN) return process.env.AUTOFIX_GITLAB_TOKEN;
  const generic = process.env.GITLAB_TOKEN;
  if (!generic) return undefined;
  const host = (u: string) => {
    try {
      return new URL(/^https?:\/\//.test(u) ? u : `https://${u}`).host.toLowerCase();
    } catch {
      return "";
    }
  };
  return host(project.api) === host(process.env.GITLAB_HOST || "gitlab.com") ? generic : undefined;
}

/** Opens a merge request and returns its web URL. */
export async function createMergeRequest(
  project: GitlabProject,
  token: string,
  mr: { source: string; target: string; title: string; description: string },
): Promise<string> {
  const res = await fetchWithRetry(`${project.api}/projects/${encodeURIComponent(project.path)}/merge_requests`, {
    method: "POST",
    headers: { "content-type": "application/json", "private-token": token },
    body: JSON.stringify({
      source_branch: mr.source,
      target_branch: mr.target,
      title: mr.title,
      description: mr.description,
      remove_source_branch: true,
    }),
  });
  const body = (await res.json().catch(() => ({}))) as { web_url?: string; message?: unknown };
  if (!res.ok || !body.web_url) throw new Error(`GitLab merge request failed (${res.status}): ${JSON.stringify(body.message ?? body)}`);
  return body.web_url;
}
