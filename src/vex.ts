import { createHash } from "node:crypto";
import type { Dependency, Finding, Vulnerability } from "./types.js";
import { osFamily, type Ecosystem } from "./versions.js";

/** OpenVEX's reasons a product is not affected. */
export const VEX_JUSTIFICATIONS = [
  "component_not_present",
  "vulnerable_code_not_present",
  "vulnerable_code_not_in_execute_path",
  "vulnerable_code_cannot_be_controlled_by_adversary",
  "inline_mitigations_already_exist",
] as const;
export type VexJustification = (typeof VEX_JUSTIFICATIONS)[number];

const PURL_TYPE: Record<string, string> = { npm: "npm", PyPI: "pypi", Go: "golang", "crates.io": "cargo", NuGet: "nuget" };

/** Package URLs for a dependency; a Debian source package yields one per installed binary. */
export function purlsOf(dep: Pick<Dependency, "ecosystem" | "name" | "version" | "binaries">): string[] {
  const family = osFamily(dep.ecosystem);
  if (family) {
    // No qualifiers: scanners compare the qualifiers a VEX purl has, and write the point release (debian-12.11).
    const namespace = dep.ecosystem.split(":")[0].toLowerCase().replace(" linux", "");
    const binaries = dep.binaries ?? [{ name: dep.name, version: dep.version }];
    return binaries.map((b) => b.purl ?? `pkg:${family}/${namespace}/${b.name}@${encodeURIComponent(b.version)}`);
  }
  const type = PURL_TYPE[dep.ecosystem];
  // Scoped npm names keep the slash between namespace and name; the `@` is encoded.
  const name = dep.name.split("/").map(encodeURIComponent).join("/");
  return [`pkg:${type}/${name}@${encodeURIComponent(dep.version)}`];
}

export interface VexStatement {
  vulnerability: { name: string; aliases?: string[] };
  products: { "@id": string; subcomponents?: { "@id": string }[] }[];
  status: "not_affected" | "fixed";
  justification?: VexJustification;
  impact_statement?: string;
  status_notes?: string;
}

/** What a statement can come from: a `not reachable` triage verdict, an accepted risk with a justification, or a verified backport. */
export interface VexSources {
  findings: Finding[];
  ignored: { ecosystem: Ecosystem; package: string; version: string; id: string; aliases: string[]; reason: string; justification?: VexJustification; until?: string }[];
  backports: { package: string; version: string; vulns: string[] }[];
}

const naming = (v: Pick<Vulnerability, "id" | "aliases">) => {
  // Scanners key most findings by CVE, so lead with it and keep every other id as an alias.
  const cve = v.aliases.find((a) => a.startsWith("CVE-")) ?? (v.id.startsWith("CVE-") ? v.id : undefined);
  const name = cve ?? v.id;
  const aliases = [...new Set([v.id, ...v.aliases])].filter((a) => a !== name);
  return { name, ...(aliases.length ? { aliases } : {}) };
};

export function vexStatements(src: VexSources, product?: string): VexStatement[] {
  const products = (purls: string[]) =>
    product ? [{ "@id": product, subcomponents: purls.map((p) => ({ "@id": p })) }] : purls.map((p) => ({ "@id": p }));
  const out: VexStatement[] = [];
  for (const f of src.findings) {
    if (f.triage?.verdict !== "not-reachable") continue;
    for (const v of f.vulns) {
      out.push({
        vulnerability: naming(v),
        products: products(purlsOf(f.dependency)),
        status: "not_affected",
        justification: "vulnerable_code_not_in_execute_path",
        impact_statement: f.triage.reasoning,
        status_notes: "Model triage of the call sites; review before relying on it.",
      });
    }
  }
  for (const i of src.ignored) {
    if (!i.justification) continue;
    out.push({
      vulnerability: naming({ id: i.id, aliases: i.aliases }),
      products: products(purlsOf({ ecosystem: i.ecosystem, name: i.package, version: i.version })),
      status: "not_affected",
      justification: i.justification,
      impact_statement: i.reason,
      ...(i.until ? { status_notes: `Accepted until ${i.until}.` } : {}),
    });
  }
  for (const b of src.backports) {
    for (const id of b.vulns) {
      out.push({
        vulnerability: { name: id },
        products: products(purlsOf({ ecosystem: "npm", name: b.package, version: b.version })),
        status: "fixed",
        status_notes: "Upstream fix backported into this version and proven by a PoC (see .autofix-cve.json).",
      });
    }
  }
  return out;
}

/** An OpenVEX v0.2.0 document; its id is a hash of the statements, so the same facts give the same id. */
export function openVex(statements: VexStatement[], now = new Date()): object {
  const hash = createHash("sha256").update(JSON.stringify(statements)).digest("hex").slice(0, 16);
  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `https://github.com/KJLavender/Auto-FIX-CVE/vex/${hash}`,
    author: "Auto-FIX-CVE",
    timestamp: now.toISOString(),
    version: 1,
    statements,
  };
}
