import { describe, expect, it } from "vitest";
import { parsePurl, readSbom } from "../src/sbom.js";

describe("parsePurl", () => {
  it("maps supported types and decodes scoped names", () => {
    expect(parsePurl("pkg:npm/%40angular/core@20.0.0?x=1")).toEqual({ type: "npm", ecosystem: "npm", name: "@angular/core", version: "20.0.0" });
    expect(parsePurl("pkg:pypi/Flask_Login@0.6.0")).toMatchObject({ ecosystem: "PyPI", name: "flask-login" });
    expect(parsePurl("pkg:golang/github.com/gin-gonic/gin@1.9.0")).toMatchObject({ ecosystem: "Go", name: "github.com/gin-gonic/gin", version: "v1.9.0" });
    expect(parsePurl("pkg:cargo/smallvec@0.6.13")).toMatchObject({ ecosystem: "crates.io", name: "smallvec" });
    expect(parsePurl("pkg:deb/debian/zlib1g@1.2.13?distro=debian-12")).toMatchObject({ type: "deb", ecosystem: undefined });
    expect(parsePurl("not-a-purl")).toBeUndefined();
  });
});

describe("readSbom", () => {
  it("reads a CycloneDX image SBOM with its dependency graph", async () => {
    const { deps, skipped } = await readSbom("test/fixtures/sbom/image.cdx.json");
    const by = (name: string) => deps.find((d) => d.name === name)!;
    expect(deps.map((d) => d.name).sort()).toEqual(["@angular/core", "express", "qs"]);
    expect(by("express")).toMatchObject({ direct: true, introducedBy: ["express"], paths: ["app/node_modules/express/package.json"] });
    expect(by("qs")).toMatchObject({ direct: false, introducedBy: ["express"] });
    expect(skipped).toEqual({ deb: 2 });
  });

  it("reads an SPDX SBOM, where CONTAINS does not make a package direct", async () => {
    const { deps, skipped } = await readSbom("test/fixtures/sbom/image.spdx.json");
    const by = (name: string) => deps.find((d) => d.name === name)!;
    expect(by("flask")).toMatchObject({ ecosystem: "PyPI", direct: true });
    expect(by("werkzeug")).toMatchObject({ direct: false, introducedBy: ["flask"] });
    expect(by("github.com/gin-gonic/gin")).toMatchObject({ ecosystem: "Go", version: "v1.9.0", direct: true });
    expect(skipped).toEqual({ maven: 1 });
  });

  it("rejects other documents", async () => {
    await expect(readSbom("package.json")).rejects.toThrow(/neither a CycloneDX nor an SPDX/);
  });
});
