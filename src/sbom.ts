import { readFile } from "node:fs/promises";
import type { Dependency, Finding } from "./types.js";
import { isDebian, normalizeName, type Ecosystem } from "./versions.js";

export interface SbomDeps {
  deps: Dependency[];
  /** Components of types this tool does not check, by purl type (e.g. `deb`, `maven`). */
  skipped: Record<string, number>;
}

const PURL_ECOSYSTEM: Record<string, Ecosystem> = { npm: "npm", pypi: "PyPI", golang: "Go", cargo: "crates.io", nuget: "NuGet" };

/**
 * `pkg:npm/%40angular/core@20.1.0?x=y` → ecosystem, name and version. Debian
 * packages (`pkg:deb/debian/libbrotli1@1.0.9-2?distro=debian-12.11`) map to
 * OSV's per-release ecosystem (`Debian:12`). Other types have no ecosystem.
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
  if (type === "deb" && segments[0]?.toLowerCase() === "debian") {
    const release = /^debian-(\d+)/i.exec(qualifiers.get("distro") ?? "")?.[1];
    if (release) {
      ecosystem = `Debian:${release}`;
      name = segments.slice(1).join("/");
      const epoch = qualifiers.get("epoch");
      if (epoch && !version.includes(":")) version = `${epoch}:${version}`;
    }
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
    // Debian advisories are per source package; group the installed binaries under it.
    const debian = isDebian(p.ecosystem);
    const name = debian ? (node.source?.name ?? p.name) : p.name;
    const version = debian ? (node.source?.version ?? p.version) : p.version;
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
    if (debian && !dep.binaries?.some((b) => b.name === p.name)) dep.binaries = [...(dep.binaries ?? []), { name: p.name, version: p.version }];
    byKey.set(key, dep);
  }
  return { deps: [...byKey.values()], skipped };
}

/**
 * `apt-get download`-style pins for the Debian packages an upgrade would fix:
 * every installed binary of the source package at the fixed version, e.g.
 * `libbrotli1=1.0.9-2+deb12u1`. Security updates give the binaries the
 * source's version; a binNMU (`+b1`) would differ and needs checking by hand.
 */
export function debianDownloadList(findings: Finding[]): string[] {
  return findings.flatMap((f) =>
    f.dependency.binaries && f.safeVersion ? f.dependency.binaries.map((b) => `${b.name}=${f.safeVersion}`) : [],
  );
}
