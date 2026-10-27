import { describe, expect, it } from "vitest";
import { osDownloadList, parsePurl, readSbom } from "../src/sbom.js";
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
    // Without a release there is no OSV ecosystem to ask.
    expect(parsePurl("pkg:deb/debian/zlib1g@1.2.13")).toMatchObject({ type: "deb", ecosystem: undefined });
    expect(parsePurl("pkg:deb/ubuntu/zlib1g@1.2.13?distro=ubuntu-22.04")).toMatchObject({ ecosystem: "Ubuntu:22.04:LTS", name: "zlib1g" });
    expect(parsePurl("pkg:deb/ubuntu/zlib1g@1.2.13?distro=ubuntu-23.10")).toMatchObject({ ecosystem: "Ubuntu:23.10" });
    expect(parsePurl("pkg:apk/alpine/libssl3@3.1.4-r0?arch=x86_64&distro=3.19.1")).toMatchObject({ ecosystem: undefined });
    expect(parsePurl("pkg:apk/alpine/libssl3@3.1.4-r0?arch=x86_64&distro=alpine-3.19.1")).toMatchObject({ ecosystem: "Alpine:v3.19", name: "libssl3" });
    expect(parsePurl("pkg:rpm/alma/openssl-libs@3.0.7-24.el9?arch=x86_64&epoch=1&distro=alma-9.3")).toEqual({
      type: "rpm",
      ecosystem: "AlmaLinux:9",
      name: "openssl-libs",
      version: "1:3.0.7-24.el9",
    });
    expect(parsePurl("pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?distro=rocky-9.3")).toMatchObject({ ecosystem: "Rocky Linux:9" });
    expect(parsePurl("pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?distro=redhat-9.3")).toMatchObject({ ecosystem: undefined });
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
    expect(osDownloadList([finding("openssl", "3.0.22-1~deb12u2"), finding("brotli"), finding("express", "4.20.0")])).toEqual([
      "libssl3=3.0.22-1~deb12u2",
      "openssl=3.0.22-1~deb12u2",
    ]);
    const rpm = {
      dependency: { ecosystem: "AlmaLinux:9", name: "openssl-libs", version: "1:3.0.7-24.el9", paths: [], direct: true, dev: false, introducedBy: [], binaries: [{ name: "openssl-libs", version: "1:3.0.7-24.el9" }] },
      safeVersion: "1:3.0.7-27.el9",
    } as unknown as Finding;
    expect(osDownloadList([rpm])).toEqual(["openssl-libs-1:3.0.7-27.el9"]);
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

describe("apk and rpm versions", () => {
  it("order like apk-tools", () => {
    const v = ["3.1.4-r1", "3.1.4_rc1-r0", "3.1.4-r0", "3.1.4_p1-r0", "3.1.10-r0", "3.1.4a-r0", "3.1-r0"];
    expect([...v].sort((a, b) => compareVersions("Alpine:v3.19", a, b))).toEqual([
      "3.1-r0",
      "3.1.4_rc1-r0",
      "3.1.4-r0",
      "3.1.4-r1",
      "3.1.4_p1-r0",
      "3.1.4a-r0",
      "3.1.10-r0",
    ]);
  });

  it("order like rpm: epoch, then version and release by rpmvercmp", () => {
    const v = ["1:3.0.7-27.el9", "3.0.7-24.el9", "1:3.0.7-24.el9", "1:3.0.7-24.el9_3.1", "1:3.0.7~beta-1.el9", "1:3.0.10-1.el9", "2:1.0-1"];
    expect([...v].sort((a, b) => compareVersions("AlmaLinux:9", a, b))).toEqual([
      "3.0.7-24.el9",
      "1:3.0.7~beta-1.el9",
      "1:3.0.7-24.el9",
      "1:3.0.7-24.el9_3.1",
      "1:3.0.7-27.el9",
      "1:3.0.10-1.el9",
      "2:1.0-1",
    ]);
  });
});
