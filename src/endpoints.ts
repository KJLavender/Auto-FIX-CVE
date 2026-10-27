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
  /** Runtime release data: a URL or a local file. */
  nodeReleases: () => process.env.AUTOFIX_NODE_RELEASES_URL || "https://nodejs.org/dist/index.json",
  nodeVulns: () => process.env.AUTOFIX_NODE_VULNS_URL || "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json",
  nodeSchedule: () => process.env.AUTOFIX_NODE_SCHEDULE_URL || "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json",
  /** `{channel}` is replaced by the .NET channel, e.g. `8.0`. */
  dotnetReleases: (channel: string) =>
    (process.env.AUTOFIX_DOTNET_RELEASES_URL || "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/{channel}/releases.json").replace(
      "{channel}",
      channel,
    ),
  /** CISA's Known Exploited Vulnerabilities catalog: a URL, a local file, or `off`. */
  kev: () => process.env.AUTOFIX_KEV_URL || "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
};
