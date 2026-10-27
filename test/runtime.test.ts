import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { parseDockerfile } from "../src/runtime/dockerfile.js";
import { applyRuntimeEdits, runtimeFails, scanRuntimes, type RuntimeFinding } from "../src/runtime/index.js";

describe("parseDockerfile", () => {
  it("reads registries with ports, digests, flags, stages and ARG defaults", () => {
    const froms = parseDockerfile(
      [
        "ARG BASE=22.1.0",
        "FROM --platform=linux/amd64 nexus:8443/library/node:${BASE}-slim AS deps",
        "FROM node@sha256:abc AS digest-only",
        "FROM deps AS app",
        "RUN true",
      ].join("\r\n"),
    );
    expect(froms.map((f) => [f.repository, f.tag, f.digest, f.stage, f.final])).toEqual([
      ["nexus:8443/library/node", "22.1.0-slim", undefined, "deps", true],
      ["node", undefined, "sha256:abc", "digest-only", false],
      ["deps", undefined, undefined, "app", true],
    ]);
    expect(froms[0].arg).toEqual({ name: "BASE", line: 1, value: "22.1.0" });
  });
});

describe("runtime scan", () => {
  let root: string;

  beforeAll(async () => {
    const data = await mkdtemp(path.join(tmpdir(), "autofix-runtime-data-"));
    const file = async (name: string, body: unknown) => {
      await writeFile(path.join(data, name), JSON.stringify(body));
      return path.join(data, name);
    };
    process.env.AUTOFIX_NODE_RELEASES_URL = await file("node-dist.json", [
      { version: "v24.2.0", date: "2026-10-21", security: true, lts: false },
      { version: "v22.3.0", date: "2026-10-21", security: true, lts: "Jod" },
      { version: "v22.2.0", date: "2026-09-01", security: false, lts: "Jod" },
      { version: "v22.1.1", date: "2026-07-01", security: true, lts: "Jod" },
      { version: "v22.1.0", date: "2026-06-01", security: false, lts: "Jod" },
    ]);
    // The index covers the July release but not the October one yet.
    process.env.AUTOFIX_NODE_VULNS_URL = await file("node-vulns.json", {
      "1": { cve: ["CVE-2026-0001"], vulnerable: "22.x", patched: "^22.1.1", description: "zlib crash", severity: "high" },
    });
    process.env.AUTOFIX_NODE_SCHEDULE_URL = await file("node-schedule.json", { v22: { end: "2027-04-30" } });
    process.env.AUTOFIX_DOTNET_RELEASES_URL = await file("dotnet-{channel}.json", {
      "eol-date": "2026-11-10",
      releases: [
        { "release-version": "8.0.33", "release-date": "2026-10-25", security: true, "cve-list": [{ "cve-id": "CVE-2026-111497" }], sdks: [{ version: "8.0.427" }, { version: "8.0.133" }] },
        { "release-version": "8.0.32", "release-date": "2026-10-13", security: true, "cve-list": [{ "cve-id": "CVE-2026-0002" }], sdks: [{ version: "8.0.426" }, { version: "8.0.132" }] },
        { "release-version": "8.0.31", "release-date": "2026-09-08", security: false, "cve-list": [], sdks: [{ version: "8.0.425" }] },
      ],
    });
    await writeFile(path.join(data, "dotnet-8.0.json"), await readFile(path.join(data, "dotnet-{channel}.json")));

    root = await mkdtemp(path.join(tmpdir(), "autofix-runtime-"));
    await mkdir(path.join(root, "api"));
    await mkdir(path.join(root, "web"));
    await mkdir(path.join(root, "node_modules", "x"), { recursive: true });
    await writeFile(path.join(root, "api", "Dockerfile"), "FROM nexus:8443/library/node:22-bookworm-slim\r\nRUN npm ci\r\n");
    await writeFile(path.join(root, "web", "Dockerfile"), "FROM node:22.1.0 AS build\nFROM nginx:1.29\n");
    await writeFile(path.join(root, "backend.Dockerfile"), "ARG V=8.0.31\nFROM mcr.microsoft.com/dotnet/sdk:8.0.132 AS build\nFROM mcr.microsoft.com/dotnet/aspnet:${V}-noble-chiseled\n");
    await writeFile(path.join(root, "node_modules", "x", "Dockerfile"), "FROM node:4\n");
  });

  it("finds pinned and floating runtimes, including releases the advisory index has not caught up with", async () => {
    const findings = await scanRuntimes(root, new Date("2026-10-27"));
    const byFile = (file: string, line = 1) => findings.find((f) => f.file === file && f.line === line)!;
    expect(findings.map((f) => `${f.file}:${f.line}`)).toEqual(["api/Dockerfile:1", "backend.Dockerfile:2", "backend.Dockerfile:3", "web/Dockerfile:1"]);

    const api = byFile("api/Dockerfile");
    expect(api.status.version).toBeUndefined();
    expect(api.shipped).toBe(true);
    expect(api.edit?.to).toBe("FROM nexus:8443/library/node:22.3.0-bookworm-slim");

    const web = byFile("web/Dockerfile");
    expect(web.shipped).toBe(false);
    expect(web.status.vulns.map((v) => [v.id, v.severity])).toEqual([
      ["NSWG-CORE-1", "HIGH"],
      ["NODE-SECURITY-22.3.0", undefined],
    ]);

    const aspnet = byFile("backend.Dockerfile", 3);
    expect(aspnet.status.vulns.map((v) => v.id)).toEqual(["CVE-2026-0002", "CVE-2026-111497"]);
    expect(aspnet.eolDays).toBe(14);
    expect(aspnet.edit).toEqual({ line: 1, from: "ARG V=8.0.31", to: "ARG V=8.0.33" });

    // A pinned SDK stays in its feature band (1xx).
    expect(byFile("backend.Dockerfile", 2).edit?.to).toBe("FROM mcr.microsoft.com/dotnet/sdk:8.0.133 AS build");
  });

  it("only fails on images that ship", async () => {
    const findings = await scanRuntimes(root, new Date("2026-10-27"));
    const failing = (level: "any" | "risk" | "none") => findings.filter((f) => runtimeFails(f, level)).map((f) => `${f.file}:${f.line}`);
    expect(failing("any")).toEqual(["backend.Dockerfile:3"]);
    // .NET release notes do not rate their CVEs, so unrated ones count.
    expect(failing("risk")).toEqual(["backend.Dockerfile:3"]);
    expect(failing("none")).toEqual([]);
    const ended: RuntimeFinding = { ...findings[0], eolDays: -1 };
    expect(runtimeFails(ended, "any")).toBe(true);
  });

  it("pins the images, keeping line endings", async () => {
    const changed = await applyRuntimeEdits(root, await scanRuntimes(root, new Date("2026-10-27")));
    expect(changed.sort()).toEqual(["api/Dockerfile", "backend.Dockerfile", "web/Dockerfile"]);
    expect(await readFile(path.join(root, "api", "Dockerfile"), "utf8")).toBe("FROM nexus:8443/library/node:22.3.0-bookworm-slim\r\nRUN npm ci\r\n");
    expect(await readFile(path.join(root, "backend.Dockerfile"), "utf8")).toContain("ARG V=8.0.33\n");
    // Pinned to the newest release, the images need nothing more.
    const again = await scanRuntimes(root, new Date("2026-10-27"));
    expect(again.filter((f) => f.edit)).toEqual([]);
  });
});
