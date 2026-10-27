import semver from "semver";

export type Ecosystem = "npm" | "PyPI" | "Go" | "crates.io" | "NuGet";

const NUGET = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** NuGet versions: SemVer 2, plus legacy ones with fewer or four numeric parts (`4.3`, `1.0.0.1`). */
export function parseNuget(v: string): { parts: [number, number, number, number]; pre?: string } | undefined {
  const m = NUGET.exec(v.trim());
  if (!m) return undefined;
  return { parts: [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0), Number(m[4] ?? 0)], pre: m[5] };
}

export function compareNuget(a: string, b: string): number {
  const x = parseNuget(a);
  const y = parseNuget(b);
  if (!x || !y) return a.localeCompare(b);
  for (let i = 0; i < 4; i++) if (x.parts[i] !== y.parts[i]) return x.parts[i] < y.parts[i] ? -1 : 1;
  // Pre-release labels order like SemVer's (and NuGet compares them case-insensitively).
  return semver.compare(`0.0.0${x.pre ? `-${x.pre.toLowerCase()}` : ""}`, `0.0.0${y.pre ? `-${y.pre.toLowerCase()}` : ""}`);
}

/** Go module versions are semver with a `v` prefix and sometimes `+incompatible`. */
function goSemver(v: string): string {
  return v.replace(/^v/, "").replace(/\+incompatible$/, "");
}

/** Versions in a form `semver` understands, for the ecosystems that use semver. */
function sv(eco: Ecosystem, v: string): string {
  return eco === "Go" ? goSemver(v) : v;
}

interface Pep440 {
  epoch: number;
  release: number[];
  /** Pre-release as [rank, number]; a=0, b=1, rc=2. */
  pre?: [number, number];
  post?: number;
  dev?: number;
}

const PEP440 =
  /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(?:post|rev|r)[-_.]?(\d*))?(?:[-_.]?dev[-_.]?(\d*))?(?:\+[a-z0-9.]+)?$/i;

const PRE_RANK: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

export function parsePep440(version: string): Pep440 | undefined {
  const m = version.trim().match(PEP440);
  if (!m) return undefined;
  const [, epoch, release, preTag, preNum, postImplicit, postNum, devNum] = m;
  return {
    epoch: epoch ? Number(epoch) : 0,
    release: release.split(".").map(Number),
    pre: preTag ? [PRE_RANK[preTag.toLowerCase()], Number(preNum || 0)] : undefined,
    post: postImplicit !== undefined ? Number(postImplicit) : postNum !== undefined ? Number(postNum || 0) : undefined,
    dev: devNum !== undefined ? Number(devNum || 0) : undefined,
  };
}

function cmp(a: number, b: number): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** PEP 440 ordering: dev < pre < final < post, with trailing release zeros ignored. */
export function comparePep440(a: string, b: string): number {
  const x = parsePep440(a);
  const y = parsePep440(b);
  if (!x || !y) return a.localeCompare(b);
  if (x.epoch !== y.epoch) return cmp(x.epoch, y.epoch);
  const len = Math.max(x.release.length, y.release.length);
  for (let i = 0; i < len; i++) {
    const c = cmp(x.release[i] ?? 0, y.release[i] ?? 0);
    if (c) return c;
  }
  // A dev release with no pre/post sorts before any pre-release of the same version.
  const phase = (v: Pep440): [number, number] => {
    if (v.pre) return [1 + v.pre[0], v.pre[1]];
    if (v.dev !== undefined && v.post === undefined) return [0, 0];
    return [4, 0];
  };
  const [px, nx] = phase(x);
  const [py, ny] = phase(y);
  if (px !== py) return cmp(px, py);
  if (nx !== ny) return cmp(nx, ny);
  const c = cmp(x.post ?? -1, y.post ?? -1);
  if (c) return c;
  return cmp(x.dev ?? Infinity, y.dev ?? Infinity);
}

export function isValidVersion(eco: Ecosystem, v: string): boolean {
  if (eco === "NuGet") return parseNuget(v) !== undefined;
  return eco === "PyPI" ? parsePep440(v) !== undefined : semver.valid(sv(eco, v)) !== null;
}

export function compareVersions(eco: Ecosystem, a: string, b: string): number {
  if (eco === "NuGet") return compareNuget(a, b);
  return eco === "PyPI" ? comparePep440(a, b) : semver.compare(sv(eco, a), sv(eco, b));
}

/**
 * Whether moving from one version to another may break callers. npm follows
 * semver (any 0.x minor counts); PyPI has no rule, so a changed major (or a
 * changed minor below 1.0) is treated as breaking, which matches common practice.
 */
export function isBreakingUpgrade(eco: Ecosystem, from: string, to: string): boolean {
  if (eco === "NuGet") {
    const a = parseNuget(from);
    const b = parseNuget(to);
    if (!a || !b) return true;
    return a.parts[0] !== b.parts[0] || (a.parts[0] === 0 && a.parts[1] !== b.parts[1]);
  }
  if (eco !== "PyPI") {
    const a = semver.parse(sv(eco, from));
    const b = semver.parse(sv(eco, to));
    if (!a || !b) return true;
    if (a.major !== b.major) return true;
    if (a.major === 0 && a.minor !== b.minor) return true;
    return a.major === 0 && a.minor === 0 && a.patch !== b.patch;
  }
  const a = parsePep440(from);
  const b = parsePep440(to);
  if (!a || !b || a.epoch !== b.epoch) return true;
  const [aMajor = 0, aMinor = 0] = a.release;
  const [bMajor = 0, bMinor = 0] = b.release;
  return aMajor !== bMajor || (aMajor === 0 && aMinor !== bMinor);
}

/** PEP 503 name normalization: `PyYAML` and `pyyaml`, or `zope.interface` and `zope-interface`, are the same project. */
export function normalizeName(eco: Ecosystem, name: string): string {
  return eco === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;
}
