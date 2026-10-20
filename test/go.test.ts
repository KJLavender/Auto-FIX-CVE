import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { defaultPackageName, findGoUsagesInSource } from "../src/impact/go.js";
import { parseGoMod } from "../src/lockfile/go.js";
import { lockfileLine } from "../src/lockfile/index.js";
import { markMentions } from "../src/scan.js";
import type { Usage, Vulnerability } from "../src/types.js";
import { compareVersions, isBreakingUpgrade } from "../src/versions.js";

const FIXTURE = path.join(import.meta.dirname, "fixtures/go-app");

describe("go.mod", () => {
  it("reads direct and indirect requirements, pseudo-versions and replacements", async () => {
    const deps = parseGoMod(
      (await readFile(path.join(FIXTURE, "go.mod"), "utf8")) +
        "\nrequire github.com/old/thing v1.0.0\nreplace golang.org/x/text => golang.org/x/text v0.3.8\n",
    );
    const by = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(by["github.com/gin-gonic/gin"]).toMatchObject({ ecosystem: "Go", version: "v1.6.0", direct: true });
    expect(by["golang.org/x/net"]).toMatchObject({ version: "v0.0.0-20200822124328-c89045814202", direct: false, introducedBy: [] });
    expect(by["golang.org/x/text"].version).toBe("v0.3.8");
    expect(by["github.com/new/thing"].version).toBe("v1.2.0");
    expect(by["github.com/old/thing"]).toBeUndefined();
  });

  it("points alerts at the requirement line", () => {
    const lines = ["require (", "\tgithub.com/gin-gonic/gin v1.6.0", ")", "require gopkg.in/yaml.v2 v2.2.2"];
    expect(lockfileLine("go", lines, "github.com/gin-gonic/gin", "v1.6.0")).toBe(2);
    expect(lockfileLine("go", lines, "gopkg.in/yaml.v2", "v2.2.2")).toBe(4);
  });
});

describe("Go versions", () => {
  it("compare with the v prefix, pseudo-versions and +incompatible", () => {
    expect(compareVersions("Go", "v1.6.0", "1.9.1")).toBe(-1);
    expect(compareVersions("Go", "v0.0.0-20200822124328-c89045814202", "v0.0.1")).toBe(-1);
    expect(compareVersions("Go", "v2.0.0+incompatible", "v2.0.1")).toBe(-1);
    expect(isBreakingUpgrade("Go", "v1.6.0", "v1.9.1")).toBe(false);
    expect(isBreakingUpgrade("Go", "v0.3.2", "v0.41.0")).toBe(true);
  });
});

describe("Go usage analysis", () => {
  it("binds default names, aliases and versioned paths, and skips blank imports' symbols", () => {
    expect(defaultPackageName("gopkg.in/yaml.v2")).toBe("yaml_v2");
    expect(defaultPackageName("github.com/go-chi/chi/v5")).toBe("chi");
    expect(defaultPackageName("github.com/gin-gonic/gin")).toBe("gin");
    const src = [
      "package main",
      "import (",
      '\t"github.com/gin-gonic/gin"',
      '\tyaml "gopkg.in/yaml.v2"',
      '\t_ "github.com/lib/pq"',
      ")",
      "func main() {",
      "\tr := gin.Default() // gin.New() in a comment is ignored",
      '\tyaml.Unmarshal(b, &c)',
      "}",
    ].join("\n");
    const usages = findGoUsagesInSource("main.go", src, ["github.com/gin-gonic/gin", "gopkg.in/yaml.v2", "github.com/lib/pq"]);
    const flat = [...usages].flatMap(([mod, list]) => list.map((u) => `${mod}:${u.line}:${u.symbol}`));
    expect(flat.sort()).toEqual(["github.com/gin-gonic/gin:8:Default", "github.com/lib/pq:5:(blank import)", "gopkg.in/yaml.v2:9:Unmarshal"]);
  });
});

describe("advisory symbols", () => {
  it("decide reachability when the advisory lists the vulnerable functions", () => {
    const vuln = (id: string, affectedSymbols: string[], details = ""): Vulnerability => ({
      id, aliases: [], summary: "", details, fixedVersions: [], fixCommits: [], affectedSymbols,
    });
    const usage = (symbol: string): Usage => ({ file: "a.go", line: 1, column: 1, specifier: "x", symbol, snippet: "", mentionedBy: [] });
    const usages = [usage("Default"), usage("File"), usage("Unmarshal")];
    // The prose mentions Unmarshal, but the symbol list is authoritative and does not include it.
    markMentions(usages, [vuln("GO-1", ["Default", "Context.File"], "calling Unmarshal(...) is unaffected")]);
    expect(usages.map((u) => u.mentionedBy.length)).toEqual([1, 1, 0]);
  });
});
