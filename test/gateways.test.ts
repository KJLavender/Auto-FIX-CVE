import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createMergeRequest, gitlabProject, gitlabToken } from "../src/gitlab.js";
import { createBackend, extractJson, OpenAiBackend } from "../src/llm/backend.js";

interface Seen {
  url: string;
  headers: IncomingMessage["headers"];
  body: Record<string, unknown>;
}

let server: Server;
let base: string;
const seen: Seen[] = [];
let replies: { status: number; body: unknown }[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let data = "";
    req.on("data", (d: Buffer) => (data += d.toString("utf8")));
    req.on("end", () => {
      seen.push({ url: req.url ?? "", headers: req.headers, body: data ? JSON.parse(data) : {} });
      const reply = replies.shift() ?? { status: 500, body: { error: { message: "no reply queued" } } };
      res.writeHead(reply.status, { "content-type": "application/json" }).end(JSON.stringify(reply.body));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

const chat = (content: string, usage = { prompt_tokens: 1_000_000, completion_tokens: 100_000 }) => ({
  status: 200,
  body: { choices: [{ message: { content } }], usage },
});

const schema = { type: "object", required: ["verdict"], properties: { verdict: { type: "string" } } };

describe("OpenAI-compatible backend", () => {
  it("asks for the schema, sends the key, and prices the tokens", async () => {
    seen.length = 0;
    replies = [chat('{"verdict":"ok"}')];
    const backend = new OpenAiBackend(`${base}/v1/`, "secret", "gpt-x", "json_schema", { input: 3, output: 15 });
    const res = await backend.complete<{ verdict: string }>({ system: "sys", prompt: "hi", schema });
    expect(res.output).toEqual({ verdict: "ok" });
    expect(res.costUsd).toBeCloseTo(3 + 1.5);
    expect(seen[0].url).toBe("/v1/chat/completions");
    expect(seen[0].headers.authorization).toBe("Bearer secret");
    expect(seen[0].body.model).toBe("gpt-x");
    expect(seen[0].body.response_format).toEqual({ type: "json_schema", json_schema: { name: "result", schema } });
  });

  it("puts the schema in the prompt when the gateway lacks structured output, and retries a bad reply once", async () => {
    seen.length = 0;
    replies = [chat("Sure! Here you go: {\"other\": 1}"), chat("```json\n{\"verdict\":\"fine\"}\n```")];
    const backend = new OpenAiBackend(base, "", "m", "none", { input: 0, output: 0 });
    const res = await backend.complete<{ verdict: string }>({ system: "sys", prompt: "hi", schema });
    expect(res.output.verdict).toBe("fine");
    expect(seen).toHaveLength(2);
    expect(seen[0].body.response_format).toBeUndefined();
    expect(seen[0].headers.authorization).toBeUndefined();
    const messages = seen[0].body.messages as { role: string; content: string }[];
    expect(messages[0].content).toContain('"required":["verdict"]');
    expect((seen[1].body.messages as unknown[]).length).toBe(4);
  });

  it("gives up after the retry and reports HTTP errors", async () => {
    replies = [chat("no json"), chat("still none")];
    const backend = new OpenAiBackend(base, "", "m", "json_object", { input: 0, output: 0 });
    await expect(backend.complete({ system: "s", prompt: "p", schema })).rejects.toThrow(/did not return valid JSON/);
    replies = [{ status: 401, body: { error: { message: "bad key" } } }];
    await expect(backend.complete({ system: "s", prompt: "p", schema })).rejects.toThrow(/401: bad key/);
  });

  it("is chosen with AUTOFIX_LLM=openai and needs a URL and model", async () => {
    process.env.AUTOFIX_LLM = "openai";
    try {
      const backend = createBackend();
      expect(backend).toBeInstanceOf(OpenAiBackend);
      await expect(new OpenAiBackend("", "", "m").complete({ system: "", prompt: "", schema })).rejects.toThrow(/AUTOFIX_OPENAI_BASE_URL/);
      await expect(new OpenAiBackend(base, "", "").complete({ system: "", prompt: "", schema })).rejects.toThrow(/AUTOFIX_MODEL/);
      process.env.AUTOFIX_LLM = "nope";
      expect(() => createBackend()).toThrow(/Unknown AUTOFIX_LLM/);
    } finally {
      delete process.env.AUTOFIX_LLM;
    }
  });

  it("extracts JSON from fenced or chatty replies", () => {
    expect(extractJson('{"a":1}')).toEqual({ a: 1 });
    expect(extractJson('Result:\n```\n{"a":2}\n```')).toEqual({ a: 2 });
    expect(extractJson('ok {"a":{"b":3}} done')).toEqual({ a: { b: 3 } });
  });
});

describe("GitLab", () => {
  it("works out the project and API from origin", () => {
    delete process.env.AUTOFIX_GITLAB_API;
    delete process.env.CI_API_V4_URL;
    expect(gitlabProject("https://oauth2:tok@devops.example.com/rd/pdmp/rd_experiment.git")).toEqual({
      api: "https://devops.example.com/api/v4",
      path: "rd/pdmp/rd_experiment",
    });
    expect(gitlabProject("git@devops.example.com:rd/app.git")).toEqual({ api: "https://devops.example.com/api/v4", path: "rd/app" });
    expect(gitlabProject("ssh://git@devops.example.com:2222/rd/app.git")?.path).toBe("rd/app");
    expect(gitlabProject("http://gitlab.local:8080/a/b")).toEqual({ api: "http://gitlab.local:8080/api/v4", path: "a/b" });
    expect(gitlabProject("not a url")).toBeUndefined();
    process.env.CI_API_V4_URL = "https://ci.example.com/api/v4/";
    expect(gitlabProject("git@x:a/b.git")?.api).toBe("https://ci.example.com/api/v4");
    delete process.env.CI_API_V4_URL;
  });

  it("sends the generic GITLAB_TOKEN only to the host it belongs to", () => {
    const company = { api: "https://devops.example.com/api/v4", path: "a/b" };
    const saved = { ...process.env };
    try {
      delete process.env.AUTOFIX_GITLAB_TOKEN;
      delete process.env.GITLAB_HOST;
      process.env.GITLAB_TOKEN = "for-gitlab-com";
      expect(gitlabToken(company)).toBeUndefined();
      expect(gitlabToken({ api: "https://gitlab.com/api/v4", path: "a/b" })).toBe("for-gitlab-com");
      process.env.GITLAB_HOST = "devops.example.com";
      expect(gitlabToken(company)).toBe("for-gitlab-com");
      process.env.AUTOFIX_GITLAB_TOKEN = "explicit";
      expect(gitlabToken({ api: "https://elsewhere/api/v4", path: "a/b" })).toBe("explicit");
    } finally {
      for (const k of ["AUTOFIX_GITLAB_TOKEN", "GITLAB_TOKEN", "GITLAB_HOST"]) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    }
  });

  it("opens a merge request through the REST API", async () => {
    seen.length = 0;
    replies = [{ status: 201, body: { web_url: "https://gitlab/x/-/merge_requests/7" } }];
    const url = await createMergeRequest({ api: `${base}/api/v4`, path: "rd/app" }, "tok", {
      source: "autofix-cve/1",
      target: "main",
      title: "Fix",
      description: "body",
    });
    expect(url).toBe("https://gitlab/x/-/merge_requests/7");
    expect(seen[0].url).toBe("/api/v4/projects/rd%2Fapp/merge_requests");
    expect(seen[0].headers["private-token"]).toBe("tok");
    expect(seen[0].body).toMatchObject({ source_branch: "autofix-cve/1", target_branch: "main", remove_source_branch: true });
    replies = [{ status: 409, body: { message: ["Another open merge request already exists"] } }];
    await expect(
      createMergeRequest({ api: `${base}/api/v4`, path: "rd/app" }, "tok", { source: "s", target: "t", title: "", description: "" }),
    ).rejects.toThrow(/409/);
  });
});
