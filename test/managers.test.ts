import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { detectChecks } from "../src/fix/context.js";
import { managerFor, splitRequirement } from "../src/fix/managers.js";
import { poetryConstraint } from "../src/fix/python-managers.js";
import type { Dependency } from "../src/types.js";

const dep = (name: string, version: string): Dependency => ({
  ecosystem: "PyPI",
  name,
  version,
  paths: [],
  direct: true,
  dev: false,
  introducedBy: [name],
});

async function project(pyproject: string): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "autofix-uv-"));
  await writeFile(path.join(dir, "pyproject.toml"), pyproject);
  return dir;
}

describe("splitRequirement", () => {
  it("keeps extras and markers apart from the version spec", () => {
    expect(splitRequirement("requests[socks]>=2.25 ; python_version>'3'")).toEqual({
      head: "requests[socks]",
      spec: ">=2.25",
      marker: "; python_version>'3'",
    });
    expect(splitRequirement("Werkzeug==2.2.3")).toEqual({ head: "Werkzeug", spec: "==2.2.3", marker: "" });
  });
});

describe("uv manager", () => {
  const PYPROJECT = [
    "[project]",
    'name = "app"',
    'dependencies = ["Werkzeug==2.2.3", "requests[socks]>=2.25 ; python_version>\'3\'"]',
    "",
    "[dependency-groups]",
    'dev = ["pytest>=8"]',
    "",
  ].join("\n");

  it("rewrites the declared requirement in place, pinned stays pinned and ranges get a floor", async () => {
    const dir = await project(PYPROJECT);
    const uv = managerFor("uv", dir);
    expect(await uv.declares(dep("werkzeug", "2.2.3"))).toBe(true);
    await uv.require(dep("werkzeug", "2.2.3"), "3.1.9", true, false);
    await uv.require(dep("requests", "2.25.0"), "2.33.0", true, false);
    const text = await readFile(path.join(dir, "pyproject.toml"), "utf8");
    expect(text).toContain('"Werkzeug==3.1.9"');
    expect(text).toContain("\"requests[socks]>=2.33.0; python_version>'3'\"");
    expect(text).toContain('dev = ["pytest>=8"]');
  });

  it("constrains transitive packages under [tool.uv], appending to an existing list", async () => {
    const dir = await project(PYPROJECT);
    const uv = managerFor("uv", dir);
    expect(await uv.declares(dep("urllib3", "1.26.20"))).toBe(false);
    await uv.require(dep("urllib3", "1.26.20"), "2.8.0", false, false);
    await uv.require(dep("idna", "2.10"), "3.15", false, false);
    const text = await readFile(path.join(dir, "pyproject.toml"), "utf8");
    expect(text).toContain('[tool.uv]\nconstraint-dependencies = ["urllib3>=2.8.0", "idna>=3.15"]');
  });

  it("refuses package managers it cannot drive", () => {
    expect(() => managerFor("requirements", ".")).toThrow(/requirements/);
  });
});

describe("poetry manager", () => {
  it("keeps the project's constraint style", () => {
    expect(poetryConstraint("^1.7.1", "2.4.0", false)).toBe("^2.4.0");
    expect(poetryConstraint("~1.7", "1.7.4", false)).toBe("~1.7.4");
    expect(poetryConstraint("1.7.1", "2.4.0", false)).toBe("2.4.0");
    expect(poetryConstraint(">=1,<3", "2.4.0", false)).toBe(">=2.4.0");
    expect(poetryConstraint("^1.7.1", "2.4.0", true)).toBe("2.4.0");
  });

  it("rewrites Poetry tables, inline tables and PEP 621 strings, but cannot override transitive packages", async () => {
    const dir = await project(
      [
        "[project]",
        'dependencies = ["requests==2.25.0"]',
        "",
        "[tool.poetry.dependencies]",
        'python = "^3.11"',
        'PyJWT = "^1.7.1"',
        'Jinja2 = { version = "~2.11", extras = ["i18n"] }',
        "",
        "[tool.poetry.group.dev.dependencies]",
        'pytest = "^6.2"',
        "",
      ].join("\n"),
    );
    const poetry = managerFor("poetry", dir);
    expect(poetry.canOverride).toBe(false);
    await poetry.require(dep("pyjwt", "1.7.1"), "2.4.0", true, false);
    await poetry.require(dep("jinja2", "2.11.2"), "2.11.3", true, false);
    await poetry.require(dep("pytest", "6.2.0"), "9.0.3", true, false);
    await poetry.require(dep("requests", "2.25.0"), "2.33.0", true, false);
    const text = await readFile(path.join(dir, "pyproject.toml"), "utf8");
    expect(text).toContain('PyJWT = "^2.4.0"');
    expect(text).toContain('Jinja2 = { version = "~2.11.3", extras = ["i18n"] }');
    expect(text).toContain('pytest = "^9.0.3"');
    expect(text).toContain('"requests==2.33.0"');
    expect(text).toContain('python = "^3.11"');
  });
});

describe("pipenv manager", () => {
  it("rewrites Pipfile entries: pins stay pinned, other specifiers become a floor", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-pipenv-"));
    await writeFile(
      path.join(dir, "Pipfile"),
      ['[packages]', 'requests = "==2.25.0"', 'urllib3 = "*"', 'Jinja2 = { version = "~=2.11", extras = ["i18n"] }', "", "[dev-packages]", 'pytest = ">=6"', ""].join("\n"),
    );
    const pipenv = managerFor("pipenv", dir);
    expect(pipenv.canOverride).toBe(false);
    expect(await pipenv.declares(dep("jinja2", "2.11.2"))).toBe(true);
    await pipenv.require(dep("requests", "2.25.0"), "2.33.0", true, false);
    await pipenv.require(dep("urllib3", "1.26.5"), "2.8.0", true, false);
    await pipenv.require(dep("jinja2", "2.11.2"), "3.1.6", true, false);
    await pipenv.require(dep("pytest", "6.2.0"), "9.0.3", true, false);
    const text = await readFile(path.join(dir, "Pipfile"), "utf8");
    expect(text).toContain('requests = "==2.33.0"');
    expect(text).toContain('urllib3 = ">=2.8.0"');
    expect(text).toContain('Jinja2 = { version = ">=3.1.6", extras = ["i18n"] }');
    expect(text).toContain('pytest = ">=9.0.3"');
  });
});

describe("detectChecks", () => {
  it("uses the project's own package manager to run its scripts", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-checks-"));
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ scripts: { build: "tsc", test: "vitest" } }));
    await writeFile(path.join(dir, "pyproject.toml"), '[dependency-groups]\ndev = ["pytest"]\n');
    expect(await detectChecks(dir, "npm")).toEqual(["npm run build", "npm test"]);
    expect(await detectChecks(dir, "pnpm")).toEqual(["pnpm run build", "pnpm test"]);
    expect(await detectChecks(dir, "yarn")).toEqual(["yarn run build", "yarn test"]);
    // The same directory also has a Python project; its checks only apply when fixing that one.
    expect(await detectChecks(dir, "uv")).toEqual(["uv run pytest -q"]);
  });

  it("skips npm's placeholder test script", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-checks-"));
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ scripts: { test: 'echo "Error: no test specified" && exit 1' } }));
    expect(await detectChecks(dir, "npm")).toEqual([]);
  });
});
