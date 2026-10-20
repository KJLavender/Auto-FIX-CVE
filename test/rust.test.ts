import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { cargoRequirement, managerFor } from "../src/fix/managers.js";
import { findRustUsagesInSource, useTreeItems } from "../src/impact/rust.js";
import { readLockfile } from "../src/lockfile/index.js";
import type { Dependency } from "../src/types.js";

const FIXTURE = path.join(import.meta.dirname, "fixtures/rust-app");

describe("Cargo.lock", () => {
  it("rebuilds the graph from the workspace crate's dependencies", async () => {
    const lock = await readLockfile(FIXTURE);
    expect(lock.kind).toBe("cargo");
    const summary = lock.deps
      .map((d) => `${d.name}@${d.version} ${d.direct ? "direct" : "transitive"} <${d.introducedBy.join("+")}>`)
      .sort();
    expect(summary).toEqual([
      "aho-corasick@0.7.20 transitive <regex>",
      "memchr@2.5.0 transitive <regex>",
      "regex-syntax@0.6.25 transitive <regex>",
      "regex@1.5.4 direct <regex>",
      "smallvec@0.6.13 direct <smallvec>",
    ]);
    expect(lock.deps.every((d) => d.ecosystem === "crates.io")).toBe(true);
  });
});

describe("Rust usage analysis", () => {
  it("expands use trees", () => {
    expect(useTreeItems("{Regex, bytes::{Regex as BytesRegex, RegexSet}}")).toEqual([
      ["Regex", "Regex"],
      ["BytesRegex", "bytes::Regex"],
      ["RegexSet", "bytes::RegexSet"],
    ]);
    expect(useTreeItems("Regex")).toEqual([["Regex", "Regex"]]);
    expect(useTreeItems("prelude::*")).toEqual([]);
    expect(useTreeItems("{self, Regex}")).toEqual([["Regex", "Regex"]]);
  });

  it("finds imports, qualified paths and aliases, with dashed crate names", () => {
    const src = [
      "use serde_json::{from_str, Value};",
      "use regex as re;",
      "fn main() {",
      "    let v: Value = from_str(input).unwrap(); // regex::Regex in a comment",
      "    let r = re::Regex::new(p);",
      "    let s = serde_json::to_string(&v);",
      "}",
    ].join("\n");
    const usages = findRustUsagesInSource("main.rs", src, ["serde-json", "regex"]);
    const flat = [...usages].flatMap(([crate, list]) => list.map((u) => `${crate}:${u.line}:${u.symbol}`));
    expect(flat.sort()).toEqual([
      "regex:5:Regex::new",
      "serde-json:1:Value",
      "serde-json:1:from_str",
      "serde-json:4:Value",
      "serde-json:4:from_str",
      "serde-json:6:to_string",
    ]);
  });
});

describe("Cargo manager", () => {
  const dep = (name: string, version: string, direct: boolean): Dependency => ({
    ecosystem: "crates.io", name, version, paths: [], direct, dev: false, introducedBy: [],
  });

  it("keeps exact pins exact", () => {
    expect(cargoRequirement("=1.5.4", "1.5.5", false)).toBe("=1.5.5");
    expect(cargoRequirement("1.5", "1.5.5", false)).toBe("1.5.5");
    expect(cargoRequirement("^1.5", "1.5.5", true)).toBe("=1.5.5");
  });

  it("rewrites plain and table requirements in Cargo.toml", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "autofix-cargo-"));
    await writeFile(
      path.join(dir, "Cargo.toml"),
      ['[package]', 'name = "x"', "", "[dependencies]", 'regex = "=1.5.4"', 'smallvec = { version = "0.6.9", features = [] }', ""].join("\n"),
    );
    const cargo = managerFor("cargo", dir);
    expect(await cargo.declares(dep("regex", "1.5.4", true))).toBe(true);
    expect(await cargo.declares(dep("memchr", "2.5.0", false))).toBe(false);
    await cargo.require(dep("regex", "1.5.4", true), "1.5.5", true, false);
    await cargo.require(dep("smallvec", "0.6.9", true), "0.6.14", true, false);
    const text = await readFile(path.join(dir, "Cargo.toml"), "utf8");
    expect(text).toContain('regex = "=1.5.5"');
    expect(text).toContain('smallvec = { version = "0.6.14", features = [] }');
  });
});
