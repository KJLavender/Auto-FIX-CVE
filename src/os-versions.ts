/**
 * Version ordering for OS package managers: apk (Alpine) and rpm (AlmaLinux,
 * Rocky Linux). dpkg lives in versions.ts next to the other ecosystems.
 */

const APK = /^(\d+(?:\.\d+)*)([a-z]?)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$/;
// apk's suffix order: pre-releases sort before the plain version, patch levels after.
const APK_SUFFIX: Record<string, number> = { alpha: -4, beta: -3, pre: -2, rc: -1, cvs: 1, svn: 2, git: 3, hg: 4, p: 5 };

export function isApkVersion(v: string): boolean {
  return APK.test(v.trim());
}

/** apk-tools ordering: numeric components, a letter, `_rc1`-style suffixes, then the `-rN` package revision. */
export function compareApk(a: string, b: string): number {
  const x = APK.exec(a.trim());
  const y = APK.exec(b.trim());
  if (!x || !y) return a.localeCompare(b);
  const nx = x[1].split(".").map(Number);
  const ny = y[1].split(".").map(Number);
  for (let i = 0; i < Math.max(nx.length, ny.length); i++) {
    const d = (nx[i] ?? -1) - (ny[i] ?? -1);
    if (d) return d < 0 ? -1 : 1;
  }
  if (x[2] !== y[2]) return x[2] < y[2] ? -1 : 1;
  const suffixes = (s: string) => [...s.matchAll(/_([a-z]+)(\d*)/g)].map((m) => [APK_SUFFIX[m[1]], Number(m[2] || 0)] as const);
  const sx = suffixes(x[3]);
  const sy = suffixes(y[3]);
  for (let i = 0; i < Math.max(sx.length, sy.length); i++) {
    // No suffix ranks between pre-releases (negative) and patch levels (positive).
    const [kx, vx] = sx[i] ?? [0, 0];
    const [ky, vy] = sy[i] ?? [0, 0];
    if (kx !== ky) return kx < ky ? -1 : 1;
    if (vx !== vy) return vx < vy ? -1 : 1;
  }
  const d = Number(x[4] ?? 0) - Number(y[4] ?? 0);
  return d ? (d < 0 ? -1 : 1) : 0;
}

/** rpmvercmp on one field: alternating digit and letter segments; `~` sorts before anything, `^` after the base. */
function rpmvercmp(a: string, b: string): number {
  if (a === b) return 0;
  let i = 0;
  let j = 0;
  const sep = /[^A-Za-z0-9~^]/;
  while (i < a.length || j < b.length) {
    while (i < a.length && sep.test(a[i])) i++;
    while (j < b.length && sep.test(b[j])) j++;
    if (a[i] === "~" || b[j] === "~") {
      if (a[i] !== "~") return 1;
      if (b[j] !== "~") return -1;
      i++;
      j++;
      continue;
    }
    if (a[i] === "^" || b[j] === "^") {
      if (i >= a.length) return -1;
      if (j >= b.length) return 1;
      if (a[i] !== "^") return 1;
      if (b[j] !== "^") return -1;
      i++;
      j++;
      continue;
    }
    if (i >= a.length || j >= b.length) break;
    const numeric = /\d/.test(a[i]);
    const take = (s: string, k: number) => {
      let e = k;
      while (e < s.length && (numeric ? /\d/.test(s[e]) : /[A-Za-z]/.test(s[e]))) e++;
      return s.slice(k, e);
    };
    const x = take(a, i);
    const y = take(b, j);
    // A numeric segment is newer than an alphabetic one.
    if (!y) return numeric ? 1 : -1;
    i += x.length;
    j += y.length;
    if (numeric) {
      const xs = x.replace(/^0+/, "");
      const ys = y.replace(/^0+/, "");
      if (xs.length !== ys.length) return xs.length < ys.length ? -1 : 1;
      if (xs !== ys) return xs < ys ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  if (i >= a.length && j >= b.length) return 0;
  return i >= a.length ? -1 : 1;
}

const RPM = /^(?:(\d+):)?([^-]+)(?:-(.+))?$/;

export function isRpmVersion(v: string): boolean {
  return RPM.test(v.trim());
}

/** rpm's `[epoch:]version[-release]` ordering. */
export function compareRpm(a: string, b: string): number {
  const x = RPM.exec(a.trim());
  const y = RPM.exec(b.trim());
  if (!x || !y) return a.localeCompare(b);
  const epoch = Number(x[1] ?? 0) - Number(y[1] ?? 0);
  if (epoch) return epoch < 0 ? -1 : 1;
  return rpmvercmp(x[2], y[2]) || (x[3] && y[3] ? rpmvercmp(x[3], y[3]) : 0);
}
