import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { detectChecks } from "../src/fix/context.js";
import { addItem, NugetManager, setItemVersion } from "../src/fix/nuget-manager.js";
import { findCsharpUsagesInSource } from "../src/impact/csharp.js";
import { detectLockfiles, lockfileLine } from "../src/lockfile/index.js";
import { parseNugetLock, parseProjectAssets } from "../src/lockfile/nuget.js";
import type { Dependency } from "../src/types.js";
import { compareVersions, isBreakingUpgrade, isValidVersion } from "../src/versions.js";

const fixture = (name: string) => readFile(path.join("test/fixtures/lockfiles", name), "utf8");

describe("NuGet versions", () => {
  it("orders legacy four-part and pre-release versions", () => {
    const sorted = ["4.5.1", "4.5.0.1", "4.5", "4.5.1-preview.2", "4.5.1-preview.10", "10.0.0", "4.5.0-rc1"].sort((a, b) =>
      compareVersions("NuGet", a, b),
    );
    expect(sorted).toEqual(["4.5.0-rc1", "4.5", "4.5.0.1", "4.5.1-preview.2", "4.5.1-preview.10", "4.5.1", "10.0.0"]);
    expect(isValidVersion("NuGet", "1.0.0.1")).toBe(true);
    expect(isValidVersion("NuGet", "[1.0, )")).toBe(false);
    expect(isBreakingUpgrade("NuGet", "12.0.1", "13.0.1")).toBe(true);
    expect(isBreakingUpgrade("NuGet", "4.5.0", "4.5.1")).toBe(false);
  });
});

describe("NuGet lockfiles", () => {
  it("reads packages.lock.json across targets, with what pulls each package in", async () => {
    const deps = parseNugetLock(await fixture("packages.lock.json"));
    const by = (n: string) => deps.find((d) => d.name === n)!;
    expect(deps.map((d) => `${d.name}@${d.version}`).sort()).toEqual([
      "Newtonsoft.Json@12.0.1",
      "Serilog.AspNetCore@8.0.0",
      "Serilog@3.1.1",
      "System.Text.Encodings.Web@4.5.0",
    ]);
    expect(by("Newtonsoft.Json")).toMatchObject({ ecosystem: "NuGet", direct: true, dev: false });
    expect(by("System.Text.Encodings.Web")).toMatchObject({ direct: false, introducedBy: ["Serilog.AspNetCore"] });
  });

  it("reads obj/project.assets.json, treating PrivateAssets=all packages as build-only", async () => {
    const deps = parseProjectAssets(await fixture("project.assets.json"));
    const by = (n: string) => deps.find((d) => d.name === n)!;
    expect(by("System.Text.Json")).toMatchObject({ direct: false, dev: false, introducedBy: ["Oracle.ManagedDataAccess.Core"] });
    expect(by("StyleCop.Analyzers.Unstable")).toMatchObject({ dev: true });
    expect(deps.some((d) => d.name === "Recipe.Abstractions")).toBe(false);
  });

  it("is detected, and code scanning alerts land on the package's entry", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-nuget-"));
    await mkdir(path.join(dir, "obj"));
    await writeFile(path.join(dir, "obj", "project.assets.json"), "{}");
    expect(detectLockfiles(dir)).toEqual([{ file: "obj/project.assets.json", kind: "nuget" }]);
    await writeFile(path.join(dir, "packages.lock.json"), "{}");
    expect(detectLockfiles(dir)).toEqual([{ file: "packages.lock.json", kind: "nuget" }]);

    const lines = (await fixture("packages.lock.json")).split("\n");
    // Not the `"System.Text.Encodings.Web": "4.5.0"` line inside Serilog.AspNetCore's dependency list.
    expect(lines[lockfileLine("nuget", lines, "System.Text.Encodings.Web", "4.5.0") - 1].trim()).toBe('"System.Text.Encodings.Web": {');
  });
});

describe("C# usages", () => {
  it("finds using directives, aliases and fully qualified names", () => {
    const source = [
      "using System;",
      "global using Newtonsoft.Json.Linq;",
      "using Json = Newtonsoft.Json.JsonConvert;",
      "using Microsoft.Extensions.Logging;",
      "class A {",
      "  object X(string s) => Json.DeserializeObject(s);",
      "  object Y(string s) => Newtonsoft.Json.JsonConvert.SerializeObject(s); // Newtonsoft.Json.Ignored",
      "}",
    ].join("\n");
    const found = findCsharpUsagesInSource("A.cs", source, ["Newtonsoft.Json", "Microsoft.Extensions.Logging.Abstractions", "Serilog"]);
    expect(found.get("Newtonsoft.Json")!.map((u) => [u.line, u.symbol])).toEqual([
      [2, "Linq"],
      [3, "JsonConvert"],
      [6, "JsonConvert.DeserializeObject"],
      [7, "JsonConvert.SerializeObject"],
    ]);
    // An `.Abstractions` package shares the namespace of the package it extends.
    expect(found.get("Microsoft.Extensions.Logging.Abstractions")!.map((u) => u.line)).toEqual([4]);
    expect(found.has("Serilog")).toBe(false);
  });
});

const dep = (name: string, version: string, direct: boolean): Dependency => ({
  ecosystem: "NuGet",
  name,
  version,
  paths: [],
  direct,
  dev: false,
  introducedBy: [name],
});

describe("NuGet fixes", () => {
  it("edits Version attributes and elements, and adds items to the right ItemGroup", () => {
    const xml = '<Project>\n  <ItemGroup>\n    <PackageReference Include="newtonsoft.json" Version="12.0.1" />\n    <PackageReference Include="Serilog">\n      <Version>3.0.0</Version>\n    </PackageReference>\n  </ItemGroup>\n</Project>\n';
    expect(setItemVersion(xml, "PackageReference", "Newtonsoft.Json", "13.0.1").xml).toContain('Include="newtonsoft.json" Version="13.0.1"');
    expect(setItemVersion(xml, "PackageReference", "Serilog", "3.1.1").xml).toContain("<Version>3.1.1</Version>");
    expect(setItemVersion(xml, "PackageReference", "Other", "1.0.0").changed).toBe(false);
    expect(addItem(xml, "PackageReference", 'Include="X" Version="1.0.0"')).toContain(
      '<ItemGroup>\n    <PackageReference Include="X" Version="1.0.0" />\n    <PackageReference Include="newtonsoft.json"',
    );
    expect(addItem("<Project>\n</Project>\n", "PackageVersion", 'Include="X" Version="1"')).toBe(
      '<Project>\n  <ItemGroup>\n    <PackageVersion Include="X" Version="1" />\n  </ItemGroup>\n</Project>\n',
    );
  });

  it("raises a reference and pins a transitive package by referencing it", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-nuget-fix-"));
    await writeFile(path.join(dir, "App.csproj"), await readFile("test/fixtures/dotnet-app/App.csproj", "utf8"));
    const pm = new NugetManager(dir);
    expect(pm.manifestFiles).toEqual(["App.csproj"]);
    expect(await pm.declares(dep("system.text.encodings.web", "4.5.0", true))).toBe(true);
    await pm.require(dep("System.Text.Encodings.Web", "4.5.0", true), "4.5.1", true);
    await pm.require(dep("System.Text.Json", "4.7.1", false), "8.0.5", false);
    const csproj = await readFile(path.join(dir, "App.csproj"), "utf8");
    expect(csproj).toContain('<PackageReference Include="System.Text.Encodings.Web" Version="4.5.1" />');
    expect(csproj).toContain('<PackageReference Include="System.Text.Json" Version="8.0.5" />');
  });

  it("uses Directory.Packages.props under Central Package Management", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "autofix-nuget-cpm-"));
    const dir = path.join(root, "src", "Api");
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(root, "Directory.Packages.props"), '<Project>\n  <ItemGroup>\n    <PackageVersion Include="Newtonsoft.Json" Version="12.0.1" />\n  </ItemGroup>\n</Project>\n');
    await writeFile(path.join(dir, "Api.csproj"), '<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n    <PackageReference Include="Newtonsoft.Json" />\n  </ItemGroup>\n</Project>\n');
    const pm = new NugetManager(dir);
    expect(pm.manifestFiles).toEqual(["Api.csproj", path.join("..", "..", "Directory.Packages.props")]);
    await pm.require(dep("Newtonsoft.Json", "12.0.1", true), "13.0.1", true);
    await pm.require(dep("System.Text.Json", "4.7.1", false), "8.0.5", false);
    const props = await readFile(path.join(root, "Directory.Packages.props"), "utf8");
    expect(props).toContain('<PackageVersion Include="Newtonsoft.Json" Version="13.0.1" />');
    expect(props).toContain('<PackageVersion Include="System.Text.Json" Version="8.0.5" />');
    expect(await readFile(path.join(dir, "Api.csproj"), "utf8")).toContain('<PackageReference Include="System.Text.Json" />');
  });

  it("builds, and tests only test projects", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-nuget-checks-"));
    await writeFile(path.join(dir, "App.csproj"), "<Project />");
    expect(await detectChecks(dir, "nuget")).toEqual(["dotnet build"]);
    await writeFile(path.join(dir, "App.csproj"), '<Project><ItemGroup><PackageReference Include="Microsoft.NET.Test.Sdk" Version="17.0.0" /></ItemGroup></Project>');
    expect(await detectChecks(dir, "nuget")).toEqual(["dotnet build", "dotnet test --no-build"]);
  });
});
