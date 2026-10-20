import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { findPythonUsagesInSource, importNames } from "../src/impact/python.js";
import { readLockfile } from "../src/lockfile/index.js";
import { readRequirements, requirementName } from "../src/lockfile/python.js";

const FIXTURES = path.join(import.meta.dirname, "fixtures");

const summary = (deps: { name: string; direct: boolean; dev: boolean }[]) =>
  deps
    .filter((d) => ["requests", "urllib3", "pyyaml", "pytest", "py"].includes(d.name))
    .map((d) => `${d.name} ${d.direct ? "direct" : "transitive"} ${d.dev ? "dev" : "prod"}`)
    .sort();

const EXPECTED = ["py transitive dev", "pytest direct dev", "pyyaml direct prod", "requests direct prod", "urllib3 transitive prod"];

// One pyproject resolved by uv, Poetry and Pipenv.
describe.each([
  ["python-app", "uv"],
  ["pylock/poetry", "poetry"],
  ["pylock/pipenv", "pipenv"],
] as const)("%s", (dir, kind) => {
  it(`reads ${kind} as PyPI dependencies`, async () => {
    const lock = await readLockfile(path.join(FIXTURES, dir));
    expect(lock.kind).toBe(kind);
    expect(lock.deps.every((d) => d.ecosystem === "PyPI")).toBe(true);
    expect(summary(lock.deps)).toEqual(EXPECTED);
    expect(lock.deps.find((d) => d.name === "pyyaml")?.version).toBe("5.3.1");
  });
});

describe("requirements.txt", () => {
  it("rebuilds the graph from pip-compile / uv export `# via` comments", async () => {
    const deps = await readRequirements(path.join(FIXTURES, "python-app"));
    const urllib3 = deps.find((d) => d.name === "urllib3")!;
    expect(urllib3).toMatchObject({ direct: false, introducedBy: ["requests"] });
    expect(deps.find((d) => d.name === "requests")).toMatchObject({ direct: true });
  });

  it("treats an unannotated file as all direct and skips unpinned lines", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-req-"));
    await writeFile(path.join(dir, "requirements.txt"), "# app deps\nDjango==3.2.0\nrequests[socks]==2.25.0 ; python_version > '3'\nflask>=2\n");
    const deps = await readRequirements(dir);
    expect(deps.map((d) => `${d.name}@${d.version} ${d.direct}`).sort()).toEqual(["django@3.2.0 true", "requests@2.25.0 true"]);
  });

  it("extracts names from PEP 508 requirements", () => {
    expect(requirementName("requests[socks]>=2.25 ; python_version>'3'")).toBe("requests");
    expect(requirementName("zope.interface==5")).toBe("zope.interface");
  });
});

describe("Python usage analysis", () => {
  const modules = new Map([
    ["pyyaml", ["yaml"]],
    ["jinja2", ["jinja2"]],
    ["requests", ["requests"]],
  ]);

  it("follows import, import-as, from-import and parenthesized imports", () => {
    const src = [
      "import yaml",
      "import requests as rq",
      "from jinja2 import (",
      "    Template,",
      "    Environment as Env,",
      ")",
      "data = yaml.load(text)  # yaml.dump in a comment is ignored",
      "rq.get(url)",
      "Template(s).render()",
      "env = Env()",
      "config.yaml_path = 'x.yaml'",
    ].join("\n");
    const usages = findPythonUsagesInSource("a.py", src, modules);
    const flat = [...usages].flatMap(([dist, list]) => list.map((u) => `${dist}:${u.line}:${u.symbol}`));
    expect(flat.sort()).toEqual(["jinja2:10:Environment", "jinja2:9:Template", "pyyaml:7:load", "requests:8:get"]);
  });

  it("maps distributions to import names", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-py-"));
    const names = await importNames(dir, ["PyYAML", "beautifulsoup4", "some-pkg"]);
    expect(Object.fromEntries(names)).toEqual({ pyyaml: ["yaml"], beautifulsoup4: ["bs4"], "some-pkg": ["some_pkg"] });
  });
});
