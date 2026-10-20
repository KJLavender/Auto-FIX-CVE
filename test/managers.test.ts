import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { managerFor, splitRequirement } from "../src/fix/managers.js";
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
    expect(() => managerFor("poetry", ".")).toThrow(/poetry/);
  });
});
