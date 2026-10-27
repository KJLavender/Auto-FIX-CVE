import { describe, expect, it } from "vitest";
import { debianDownloadList, parsePurl, readSbom } from "../src/sbom.js";
import type { Finding } from "../src/types.js";
import { compareVersions } from "../src/versions.js";

describe("parsePurl", () => {
  it("maps supported types and decodes scoped names", () => {
    expect(parsePurl("pkg:npm/%40angular/core@20.0.0?x=1")).toEqual({ type: "npm", ecosystem: "npm", name: "@angular/core", version: "20.0.0" });
    expect(parsePurl("pkg:pypi/Flask_Login@0.6.0")).toMatchObject({ ecosystem: "PyPI", name: "flask-login" });
    expect(parsePurl("pkg:golang/github.com/gin-gonic/gin@1.9.0")).toMatchObject({ ecosystem: "Go", name: "github.com/gin-gonic/gin", version: "v1.9.0" });
    expect(parsePurl("pkg:cargo/smallvec@0.6.13")).toMatchObject({ ecosystem: "crates.io", name: "smallvec" });
    expect(parsePurl("pkg:deb/debian/libssl3@3.0.11-1~deb12u1?arch=amd64&distro=debian-12.11")).toEqual({
      type: "deb",
      ecosystem: "Debian:12",
      name: "libssl3",
      version: "3.0.11-1~deb12u1",
    });
    expect(parsePurl("pkg:deb/debian/zlib1g@1.2.13.dfsg-1?distro=debian-12&epoch=1")).toMatchObject({ version: "1:1.2.13.dfsg-1" });
    // Without a release there is no OSV ecosystem to ask; Ubuntu is not covered.
    expect(parsePurl("pkg:deb/debian/zlib1g@1.2.13")).toMatchObject({ type: "deb", ecosystem: undefined });
    expect(parsePurl("pkg:deb/ubuntu/zlib1g@1.2.13?distro=ubuntu-22.04")).toMatchObject({ ecosystem: undefined });
    expect(parsePurl("not-a-purl")).toBeUndefined();
  });
});

describe("readSbom", () => {
  it("reads a CycloneDX image SBOM with its dependency graph", async () => {
    const { deps, skipped } = await readSbom("test/fixtures/sbom/image.cdx.json");
    const by = (name: string) => deps.find((d) => d.name === name)!;
    expect(deps.map((d) => d.name).sort()).toEqual(["@angular/core", "brotli", "express", "openssl", "qs"]);
    expect(by("express")).toMatchObject({ direct: true, introducedBy: ["express"], paths: ["app/node_modules/express/package.json"] });
    expect(by("qs")).toMatchObject({ direct: false, introducedBy: ["express"] });
    // Debian binaries are grouped under the source package their advisories are about.
    expect(by("openssl")).toMatchObject({
      ecosystem: "Debian:12",
      version: "3.0.11-1~deb12u1",
      binaries: [
        { name: "libssl3", version: "3.0.11-1~deb12u1" },
        { name: "openssl", version: "3.0.11-1~deb12u1" },
      ],
    });
    expect(by("brotli")).toMatchObject({ version: "1.0.9-2", binaries: [{ name: "libbrotli1", version: "1.0.9-2+b6" }] });
    expect(skipped).toEqual({ rpm: 1 });
  });

  it("reads an SPDX SBOM, where CONTAINS does not make a package direct", async () => {
    const { deps, skipped } = await readSbom("test/fixtures/sbom/image.spdx.json");
    const by = (name: string) => deps.find((d) => d.name === name)!;
    expect(by("flask")).toMatchObject({ ecosystem: "PyPI", direct: true });
    expect(by("werkzeug")).toMatchObject({ direct: false, introducedBy: ["flask"] });
    expect(by("github.com/gin-gonic/gin")).toMatchObject({ ecosystem: "Go", version: "v1.9.0", direct: true });
    expect(by("brotli")).toMatchObject({ ecosystem: "Debian:12", version: "1.0.9-2", binaries: [{ name: "libbrotli1" }] });
    expect(skipped).toEqual({ maven: 1 });
  });

  it("lists the fixed binaries to download for an offline mirror", async () => {
    const { deps } = await readSbom("test/fixtures/sbom/image.cdx.json");
    const finding = (name: string, safeVersion?: string) => ({ dependency: deps.find((d) => d.name === name)!, safeVersion }) as Finding;
    expect(debianDownloadList([finding("openssl", "3.0.22-1~deb12u2"), finding("brotli"), finding("express", "4.20.0")])).toEqual([
      "libssl3=3.0.22-1~deb12u2",
      "openssl=3.0.22-1~deb12u2",
    ]);
  });

  it("rejects other documents", async () => {
    await expect(readSbom("package.json")).rejects.toThrow(/neither a CycloneDX nor an SPDX/);
  });
});

describe("Debian versions", () => {
  it("order like dpkg: epochs, ~ before anything, letters before symbols", () => {
    const v = ["1:0.1", "1.0.9-2+deb12u1", "1.0.10-1", "1.0.9~rc1-1", "1.0.9-2", "1.0.9-10", "1.0.9-2+b6", "1.0.9a-1"];
    expect([...v].sort((a, b) => compareVersions("Debian:12", a, b))).toEqual([
      "1.0.9~rc1-1",
      "1.0.9-2",
      "1.0.9-2+b6",
      "1.0.9-2+deb12u1",
      "1.0.9-10",
      "1.0.9a-1",
      "1.0.10-1",
      "1:0.1",
    ]);
    expect(compareVersions("Debian:12", "3.0.11-1~deb12u1", "3.0.11-1")).toBe(-1);
    expect(compareVersions("Debian:12", "1.0-1", "1.0-1")).toBe(0);
  });
});
