import { readFile } from "node:fs/promises";
import type { Dependency, Finding } from "./types.js";
import { normalizeName, osFamily, type Ecosystem, type OsEcosystem } from "./versions.js";

export interface SbomDeps {
  deps: Dependency[];
  /** Components of types this tool does not check, by purl type (e.g. `deb`, `maven`). */
  skipped: Record<string, number>;
}

const PURL_ECOSYSTEM: Record<string, Ecosystem> = { npm: "npm", pypi: "PyPI", golang: "Go", cargo: "crates.io", nuget: "NuGet" };

/**
 * OSV's per-release ecosystem for an OS package, from the purl's type,
 * namespace and `distro` qualifier (as Trivy writes them): `debian-12.11` →
 * `Debian:12`, `ubuntu-22.04` → `Ubuntu:22.04:LTS`, `alpine-3.20.3` →
 * `Alpine:v3.20`, `alma-9.4` → `AlmaLinux:9`, `rocky-9.4` → `Rocky Linux:9`.
 */
export function osEcosystem(type: string, namespace: string, distro: string): OsEcosystem | undefined {
  const ns = namespace.toLowerCase();
  const release = /-(\d+(?:\.\d+)*)$/.exec(distro)?.[1];
  if (!release) return undefined;
  const [major, minor = "0"] = release.split(".");
  if (type === "deb" && ns === "debian") return `Debian:${major}`;
  if (type === "deb" && ns === "ubuntu") {
    const version = `${major}.${minor.padStart(2, "0")}`;
    // LTS releases are the April ones of even years.
    return minor === "04" && Number(major) % 2 === 0 ? `Ubuntu:${version}:LTS` : `Ubuntu:${version}`;
  }
  if (type === "apk" && ns === "alpine") return `Alpine:v${major}.${minor}`;
  if (type === "rpm" && /^(alma|almalinux)$/.test(ns)) return `AlmaLinux:${major}`;
  if (type === "rpm" && /^(rocky|rocky-linux|rockylinux)$/.test(ns)) return `Rocky Linux:${major}`;
  return undefined;
}

/**
 * `pkg:npm/%40angular/core@20.1.0?x=y` → ecosystem, name and version. OS
 * packages get OSV's per-release ecosystem (see `osEcosystem`); other types,
 * and OS packages without a known release, have none.
 */
export function parsePurl(purl: string): { type: string; ecosystem?: Ecosystem; name: string; version: string } | undefined {
  const m = /^pkg:([^/]+)\/([^@?#]+)@([^?#]+)(?:\?([^#]*))?/.exec(purl);
  if (!m) return undefined;
  const type = m[1].toLowerCase();
  const segments = m[2].split("/").map(decodeURIComponent);
  let name = segments.join("/");
  let version = decodeURIComponent(m[3]);
  const qualifiers = new URLSearchParams(m[4] ?? "");
  let ecosystem: Ecosystem | undefined = PURL_ECOSYSTEM[type];
  const os = segments.length > 1 ? osEcosystem(type, segments[0], qualifiers.get("distro") ?? "") : undefined;
  if (os) {
    ecosystem = os;
    name = segments.slice(1).join("/");
    const epoch = qualifiers.get("epoch");
    if (epoch && epoch !== "0" && !version.includes(":")) version = `${epoch}:${version}`;
  }
  if (ecosystem === "Go" && !version.startsWith("v")) version = `v${version}`;
  return { type, ecosystem, name: ecosystem ? normalizeName(ecosystem, name) : name, version };
}

interface Node {
  ref: string;
  purl?: string;
  paths: string[];
  /** Source package name and version (Debian), when the SBOM records them. */
  source?: { name: string; version?: string };
}

/** Trivy's properties for the source package a binary deb was built from. */
function sourceFromProperties(props: { name: string; value: string }[]): Node["source"] {
  const get = (n: string) => props.find((p) => p.name === `aquasecurity:trivy:${n}`)?.value;
  const name = get("SrcName");
  if (!name) return undefined;
  const version = get("SrcVersion");
  const release = get("SrcRelease");
  const epoch = get("SrcEpoch");
  const full = version && `${epoch && epoch !== "0" ? `${epoch}:` : ""}${version}${release ? `-${release}` : ""}`;
  return { name, version: full };
}

interface CycloneDx {
  bomFormat?: string;
  components?: { "bom-ref"?: string; purl?: string; properties?: { name: string; value: string }[] }[];
  dependencies?: { ref: string; dependsOn?: string[] }[];
}

interface Spdx {
  spdxVersion?: string;
  packages?: { SPDXID: string; externalRefs?: { referenceType: string; referenceLocator: string }[]; sourceInfo?: string }[];
  relationships?: { spdxElementId: string; relationshipType: string; relatedSpdxElement: string }[];
}

const LOCATION_PROPS = new Set(["aquasecurity:trivy:PkgPath", "aquasecurity:trivy:FilePath"]);

/** Reads the packages of a CycloneDX or SPDX JSON SBOM, e.g. from `trivy image --format cyclonedx` or a Harbor SBOM. */
export async function readSbom(file: string): Promise<SbomDeps> {
  const doc = JSON.parse(await readFile(file, "utf8")) as CycloneDx & Spdx;
  const nodes = new Map<string, Node>();
  const edges: [string, string][] = [];
  if (doc.bomFormat === "CycloneDX") {
    for (const c of doc.components ?? []) {
      const ref = c["bom-ref"] ?? c.purl;
      if (!ref) continue;
      const paths = (c.properties ?? []).filter((p) => LOCATION_PROPS.has(p.name)).map((p) => p.value);
      nodes.set(ref, { ref, purl: c.purl, paths, source: sourceFromProperties(c.properties ?? []) });
    }
    for (const d of doc.dependencies ?? []) for (const child of d.dependsOn ?? []) edges.push([d.ref, child]);
  } else if (doc.spdxVersion) {
    for (const p of doc.packages ?? []) {
      const purl = p.externalRefs?.find((r) => r.referenceType === "purl")?.referenceLocator;
      // Trivy writes `built package from: brotli 1.0.9-2` for OS packages.
      const built = /built package from:\s*(\S+)(?:\s+(\S+))?/i.exec(p.sourceInfo ?? "");
      nodes.set(p.SPDXID, { ref: p.SPDXID, purl, paths: [], source: built ? { name: built[1], version: built[2] } : undefined });
    }
    for (const r of doc.relationships ?? []) {
      // CONTAINS links an application to every package in it, transitive ones too, so only dependency edges count.
      if (r.relationshipType === "DEPENDS_ON") edges.push([r.spdxElementId, r.relatedSpdxElement]);
      else if (r.relationshipType === "DEPENDENCY_OF") edges.push([r.relatedSpdxElement, r.spdxElementId]);
    }
  } else {
    throw new Error(`${file} is neither a CycloneDX nor an SPDX JSON document.`);
  }

  const parents = new Map<string, string[]>();
  for (const [from, to] of edges) parents.set(to, [...(parents.get(to) ?? []), from]);
  const parsed = new Map([...nodes.values()].map((n) => [n.ref, n.purl ? parsePurl(n.purl) : undefined]));
  const isPackage = (ref: string) => parsed.get(ref)?.ecosystem !== undefined;
  // Direct: pulled in by the image or an application (a lockfile), not by another package.
  const isDirect = (ref: string) => {
    const ps = parents.get(ref) ?? [];
    return ps.length === 0 || ps.some((p) => !isPackage(p));
  };
  const directAncestors = (ref: string): string[] => {
    const found = new Set<string>();
    const seen = new Set<string>([ref]);
    const queue = [...(parents.get(ref) ?? [])];
    while (queue.length) {
      const p = queue.shift()!;
      if (seen.has(p) || !isPackage(p)) continue;
      seen.add(p);
      if (isDirect(p)) found.add(parsed.get(p)!.name);
      queue.push(...(parents.get(p) ?? []));
    }
    return [...found];
  };

  const skipped: Record<string, number> = {};
  const byKey = new Map<string, Dependency>();
  for (const node of nodes.values()) {
    const p = parsed.get(node.ref);
    if (!p) continue;
    if (!p.ecosystem) {
      skipped[p.type] = (skipped[p.type] ?? 0) + 1;
      continue;
    }
    const direct = isDirect(node.ref);
    // Debian, Ubuntu and Alpine advisories are per source package; group the installed binaries
    // under it. AlmaLinux and Rocky advisories name binary packages, so those stay as they are.
    const family = osFamily(p.ecosystem);
    const bySource = family === "deb" || family === "apk";
    const name = bySource ? (node.source?.name ?? p.name) : p.name;
    const version = bySource ? (node.source?.version ?? p.version) : p.version;
    const key = `${p.ecosystem}:${name}@${version}`;
    const dep: Dependency = byKey.get(key) ?? {
      ecosystem: p.ecosystem,
      name,
      version,
      paths: [],
      direct: false,
      dev: false,
      introducedBy: [],
    };
    // An image can hold the same package in several applications; merge them.
    dep.direct ||= direct;
    dep.paths = [...new Set([...dep.paths, ...node.paths])];
    dep.introducedBy = [...new Set([...dep.introducedBy, ...(direct ? [name] : directAncestors(node.ref))])];
    if (family && !dep.binaries?.some((b) => b.name === p.name)) {
      // The purl without qualifiers, as other tools write it for this package.
      dep.binaries = [...(dep.binaries ?? []), { name: p.name, version: p.version, purl: node.purl?.split("?")[0] }];
    }
    byKey.set(key, dep);
  }
  return { deps: [...byKey.values()], skipped };
}

/**
 * Pins for the OS packages an upgrade would fix, one per installed binary, in
 * the format the package manager takes: `libbrotli1=1.0.9-2+deb12u1` (apt),
 * `libssl3=3.1.7-r1` (apk), `openssl-libs-1:3.0.7-27.el9` (dnf). Security
 * updates give a source package's binaries its version; a Debian binNMU
 * (`+b1`) would differ and needs checking by hand.
 */
export function osDownloadList(findings: Finding[]): string[] {
  return findings.flatMap((f) => {
    const family = osFamily(f.dependency.ecosystem);
    if (!family || !f.safeVersion || !f.dependency.binaries) return [];
    return f.dependency.binaries.map((b) => (family === "rpm" ? `${b.name}-${f.safeVersion}` : `${b.name}=${f.safeVersion}`));
  });
}
