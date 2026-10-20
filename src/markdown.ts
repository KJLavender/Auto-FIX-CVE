import { severityBreakdown } from "./report.js";
import type { Finding } from "./types.js";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"];

function worstSeverity(f: Finding): string {
  const found = f.vulns.map((v) => v.severity?.toUpperCase() ?? "").filter(Boolean);
  return SEVERITY_ORDER.find((s) => found.includes(s)) ?? "UNKNOWN";
}

function reach(f: Finding): string {
  if (f.triage) return `triage: **${f.triage.verdict}**`;
  return f.reachability === "likely" ? "**likely reachable**" : f.reachability === "imported" ? "imported" : "not imported";
}

function where(f: Finding): string {
  const sites = [...f.usages, ...f.via.flatMap((v) => v.usages)];
  if (!sites.length) return "";
  const shown = sites.slice(0, 3).map((u) => `\`${u.file}:${u.line}\``);
  return shown.join("<br>") + (sites.length > 3 ? `<br>+${sites.length - 3} more` : "");
}

/** A Markdown report for CI job summaries and PR comments: one table row per vulnerable package. */
export function toMarkdown(projects: { lockfile: string; findings: Finding[] }[]): string {
  const out: string[] = ["## Auto-FIX-CVE scan", ""];
  for (const { lockfile, findings } of projects) {
    if (projects.length > 1) out.push(`### \`${lockfile}\``, "");
    if (findings.length === 0) {
      out.push("No known vulnerabilities.", "");
      continue;
    }
    const total = findings.reduce((n, f) => n + f.vulns.length, 0);
    out.push(`${total} vulnerabilities in ${findings.length} packages (${severityBreakdown(findings)}).`, "");
    out.push("| Package | Severity | Vulnerabilities | Reachability | Used at | Fix |");
    out.push("|---|---|---|---|---|---|");
    for (const f of findings) {
      const d = f.dependency;
      const ids = f.vulns.map((v) => v.aliases.find((a) => a.startsWith("CVE-")) ?? v.id);
      const vulns = ids.slice(0, 3).join(", ") + (ids.length > 3 ? ` +${ids.length - 3}` : "");
      const kind = d.direct ? "" : ` (via ${d.introducedBy.join(", ")})`;
      const fix = f.safeVersion ? `→ ${f.safeVersion}${f.breaking ? " (breaking)" : ""}` : "no fixed release";
      out.push(`| \`${d.name}@${d.version}\`${kind} | ${worstSeverity(f)} | ${vulns} | ${reach(f)} | ${where(f)} | ${fix} |`);
    }
    out.push("");
  }
  return out.join("\n");
}
