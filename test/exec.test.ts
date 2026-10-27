import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { projectEnv, run, splitArgs, wrapCommand } from "../src/fix/exec.js";

const saved = { ...process.env };
afterEach(() => {
  for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
  Object.assign(process.env, saved);
});

describe("projectEnv", () => {
  it("keeps what builds need and drops credentials", () => {
    const env = projectEnv({
      PATH: "/bin",
      HOME: "/home/u",
      npm_config_registry: "https://nexus/npm/",
      "npm_config_//nexus/:_authToken": "secret",
      GITHUB_TOKEN: "ghp_x",
      AUTOFIX_OPENAI_API_KEY: "sk-x",
      AWS_SECRET_ACCESS_KEY: "aws",
      GOPROXY: "https://proxy",
      CARGO_REGISTRIES_X_TOKEN: "t",
      NPM_TOKEN: "npm",
    });
    expect(env.PATH).toBe("/bin");
    expect(env.npm_config_registry).toBe("https://nexus/npm/");
    expect(env.GOPROXY).toBe("https://proxy");
    for (const k of ["npm_config_//nexus/:_authToken", "GITHUB_TOKEN", "AUTOFIX_OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "CARGO_REGISTRIES_X_TOKEN", "NPM_TOKEN"]) {
      expect(env[k]).toBeUndefined();
    }
    expect(env.CI).toBe("1");
  });

  it("passes what the user names, and turns install scripts off on request", () => {
    const env = projectEnv({ PATH: "/bin", NPM_TOKEN: "npm", AUTOFIX_PASS_ENV: "npm_token, OTHER", AUTOFIX_IGNORE_SCRIPTS: "1" });
    expect(env.NPM_TOKEN).toBe("npm");
    expect(env.npm_config_ignore_scripts).toBe("true");
    expect(env.YARN_ENABLE_SCRIPTS).toBe("false");
  });
});

describe("sandbox wrapper", () => {
  it("turns the template into a program and arguments, with the command last", () => {
    expect(splitArgs(`docker run --rm -v "{dir}:/work" -w /work 'node:22 slim' sh -c`)).toEqual([
      "docker", "run", "--rm", "-v", "{dir}:/work", "-w", "/work", "node:22 slim", "sh", "-c",
    ]);
    expect(wrapCommand("npm test", "/p", "docker run -v {dir}:/w img sh -c")).toEqual({
      file: "docker",
      args: ["run", "-v", "/p:/w", "img", "sh", "-c", "npm test"],
      shell: false,
    });
    expect(wrapCommand("npm test", "/p", "")).toEqual({ file: "npm test", args: [], shell: true });
  });
});

describe("run", () => {
  const probe = 'node -e "console.log(JSON.stringify({ gh: process.env.GITHUB_TOKEN ?? null, path: Boolean(process.env.PATH || process.env.Path) }))"';

  it("hides the caller's credentials from project commands but not from trusted tools", async () => {
    process.env.GITHUB_TOKEN = "ghp_should_not_leak";
    const untrusted = await run(probe, process.cwd());
    expect(JSON.parse(untrusted.output.trim())).toEqual({ gh: null, path: true });
    const trusted = await run(probe, process.cwd(), 60_000, { trusted: true });
    expect(JSON.parse(trusted.output.trim()).gh).toBe("ghp_should_not_leak");
  });

  it("runs project commands through the wrapper", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-wrap-"));
    const wrapper = path.join(dir, "wrapper.cjs");
    await writeFile(wrapper, "console.log(JSON.stringify(process.argv.slice(2)));");
    process.env.AUTOFIX_EXEC_WRAPPER = `"${process.execPath}" "${wrapper}" --dir {dir} --`;
    const res = await run("npm install", dir);
    expect(JSON.parse(res.output.trim())).toEqual(["--dir", dir, "--", "npm install"]);
    // Our own tools are not wrapped.
    const git = await run("node -e \"console.log('direct')\"", dir, 60_000, { trusted: true });
    expect(git.output.trim()).toBe("direct");
  });
});
