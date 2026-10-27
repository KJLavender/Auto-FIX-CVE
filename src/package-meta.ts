import { endpoints } from "./endpoints.js";
import { loadJson } from "./http.js";
import type { Ecosystem } from "./versions.js";

/** What a registry says about one release, for admission checks. */
export interface PackageMeta {
  exists: boolean;
  /** The version looked at: the one asked for, or the latest. */
  version: string;
  latest?: string;
  published?: string;
  /** SPDX expression when the registry gives one, otherwise its free text normalised where possible. */
  license?: string;
  /** Why the release is deprecated (npm, NuGet), when it is. */
  deprecated?: string;
  /** Pulled by its author (PyPI, crates.io) or unlisted (NuGet). */
  yanked?: boolean;
}

export type MetaFetcher = (ecosystem: Ecosystem, name: string, version?: string) => Promise<PackageMeta>;

const FREE_TEXT_LICENSES: [RegExp, string][] = [
  [/^(the )?mit( license)?$/i, "MIT"],
  [/^apache(-| )?(license,? )?(version )?2(\.0)?$|^apache software license$/i, "Apache-2.0"],
  [/^bsd(-| )?3(-clause)?$|^new bsd|^(modified|revised) bsd/i, "BSD-3-Clause"],
  [/^bsd(-| )?2(-clause)?$|^simplified bsd/i, "BSD-2-Clause"],
  [/^isc( license)?$/i, "ISC"],
  [/^mpl(-| )?2(\.0)?$|^mozilla public license 2\.0/i, "MPL-2.0"],
  [/^(gnu )?lgpl(v| )?3/i, "LGPL-3.0"],
  [/^(gnu )?gpl(v| )?3/i, "GPL-3.0"],
  [/^(gnu )?gpl(v| )?2/i, "GPL-2.0"],
];

/** Free-text license fields (`Apache 2.0`, `MIT License`) mapped to SPDX ids; unknown text is kept as is. */
export function normalizeLicense(text: string | undefined): string | undefined {
  const t = text?.trim();
  if (!t) return undefined;
  // PyPI projects often paste the whole license text; only a short field is an identifier.
  if (t.length > 80) return undefined;
  return FREE_TEXT_LICENSES.find(([re]) => re.test(t))?.[1] ?? t;
}

/** PyPI classifiers name the license when the field is empty: `License :: OSI Approved :: MIT License`. */
function licenseFromClassifiers(classifiers: string[] | undefined): string | undefined {
  const c = classifiers?.find((x) => x.startsWith("License :: "));
  return c ? normalizeLicense(c.split(" :: ").pop()) : undefined;
}

async function npm(name: string, version?: string): Promise<PackageMeta> {
  const doc = await loadJson<{
    "dist-tags"?: { latest?: string };
    versions?: Record<string, { license?: string | { type?: string }; deprecated?: string }>;
    time?: Record<string, string>;
  }>(`${endpoints.npm()}/${name.replace("/", "%2f")}`);
  const latest = doc?.["dist-tags"]?.latest;
  const v = version ?? latest ?? "";
  const release = doc?.versions?.[v];
  if (!release) return { exists: false, version: v, latest };
  const license = typeof release.license === "string" ? release.license : release.license?.type;
  return { exists: true, version: v, latest, published: doc?.time?.[v], license: normalizeLicense(license), deprecated: release.deprecated || undefined };
}

async function pypi(name: string, version?: string): Promise<PackageMeta> {
  const project = await loadJson<{ info?: { version?: string } }>(`${endpoints.pypi()}/${name}/json`);
  const latest = project?.info?.version;
  const v = version ?? latest ?? "";
  const doc = await loadJson<{
    info?: { license?: string; license_expression?: string; classifiers?: string[]; yanked?: boolean };
    urls?: { upload_time_iso_8601?: string }[];
  }>(`${endpoints.pypi()}/${name}/${v}/json`);
  if (!doc?.info) return { exists: false, version: v, latest };
  const license = doc.info.license_expression || normalizeLicense(doc.info.license) || licenseFromClassifiers(doc.info.classifiers);
  return { exists: true, version: v, latest, published: doc.urls?.[0]?.upload_time_iso_8601, license, yanked: doc.info.yanked || undefined };
}

async function crates(name: string, version?: string): Promise<PackageMeta> {
  const crate = await loadJson<{ crate?: { max_stable_version?: string; max_version?: string } }>(`${endpoints.cratesApi()}/crates/${name}`);
  const latest = crate?.crate?.max_stable_version ?? crate?.crate?.max_version;
  const v = version ?? latest ?? "";
  const doc = await loadJson<{ version?: { license?: string; created_at?: string; yanked?: boolean } }>(`${endpoints.cratesApi()}/crates/${name}/${v}`);
  if (!doc?.version) return { exists: false, version: v, latest };
  return { exists: true, version: v, latest, published: doc.version.created_at, license: doc.version.license, yanked: doc.version.yanked || undefined };
}

/** Module proxy paths escape capitals: `github.com/Azure/x` → `github.com/!azure/x`. */
export function goEscape(path: string): string {
  return path.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

async function go(name: string, version?: string): Promise<PackageMeta> {
  const latestInfo = await loadJson<{ Version?: string }>(`${endpoints.goProxy()}/${goEscape(name)}/@latest`);
  const latest = latestInfo?.Version;
  const v = version ? (version.startsWith("v") ? version : `v${version}`) : (latest ?? "");
  const info = await loadJson<{ Version?: string; Time?: string }>(`${endpoints.goProxy()}/${goEscape(name)}/@v/${v}.info`);
  // The module proxy has no license data.
  return info?.Version ? { exists: true, version: v, latest, published: info.Time } : { exists: false, version: v, latest };
}

async function nuget(name: string, version?: string): Promise<PackageMeta> {
  const id = name.toLowerCase();
  // nuget.org's layout: `<base>-flatcontainer` for versions, `<base>/registration5-semver1` for release data.
  const index = await loadJson<{ versions?: string[] }>(`${endpoints.nuget()}-flatcontainer/${id}/index.json`);
  const stable = (index?.versions ?? []).filter((x) => !x.includes("-"));
  const latest = stable.at(-1) ?? index?.versions?.at(-1);
  const v = version ?? latest ?? "";
  const leaf = await loadJson<{ catalogEntry?: string; listed?: boolean; published?: string }>(`${endpoints.nuget()}/registration5-semver1/${id}/${v.toLowerCase()}.json`);
  if (!leaf) return { exists: false, version: v, latest };
  const entry = leaf.catalogEntry
    ? await loadJson<{ licenseExpression?: string; deprecation?: { reasons?: string[]; message?: string } }>(leaf.catalogEntry)
    : undefined;
  const deprecation = entry?.deprecation;
  return {
    exists: true,
    version: v,
    latest,
    published: leaf.published,
    license: entry?.licenseExpression || undefined,
    deprecated: deprecation ? deprecation.message || deprecation.reasons?.join(", ") || "deprecated" : undefined,
    yanked: leaf.listed === false || undefined,
  };
}

/** Registry metadata for one release; `version` omitted means the latest stable one. */
export const fetchPackageMeta: MetaFetcher = async (ecosystem, name, version) => {
  switch (ecosystem) {
    case "npm":
      return npm(name, version);
    case "PyPI":
      return pypi(name, version);
    case "crates.io":
      return crates(name, version);
    case "Go":
      return go(name, version);
    case "NuGet":
      return nuget(name, version);
    default:
      return { exists: false, version: version ?? "" };
  }
};
