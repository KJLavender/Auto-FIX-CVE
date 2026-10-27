/**
 * Every outside service the tool talks to, overridable by environment
 * variable so it can run behind a mirror (e.g. Nexus) or fully offline.
 * Read on each call, so tests and long-lived processes see changes.
 */
const base = (value: string | undefined, fallback: string) => (value || fallback).replace(/\/+$/, "");

export const endpoints = {
  osv: () => base(process.env.AUTOFIX_OSV_URL, "https://api.osv.dev/v1"),
  // npm exports the configured registry to scripts and npx, so a project's .npmrc mirror is honoured too.
  npm: () => base(process.env.AUTOFIX_NPM_REGISTRY ?? process.env.npm_config_registry, "https://registry.npmjs.org"),
  pypi: () => base(process.env.AUTOFIX_PYPI_URL, "https://pypi.org/pypi"),
  crates: () => base(process.env.AUTOFIX_CRATES_INDEX, "https://index.crates.io"),
  github: () => base(process.env.AUTOFIX_GITHUB_API, "https://api.github.com"),
  /** CISA's Known Exploited Vulnerabilities catalog: a URL, a local file, or `off`. */
  kev: () => process.env.AUTOFIX_KEV_URL || "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
};
