import pc from "picocolors";
import type { FixResult, FixStatus, PlanStep } from "./fix/upgrade.js";
import type { Finding, Reachability } from "./types.js";

const STATUS_LABEL: Record<FixStatus, string> = {
  fixed: pc.green("FIXED"),
  skipped: pc.yellow("SKIPPED"),
  failed: pc.red("FAILED"),
};

export function formatPlan(plan: PlanStep[], checks: string[]): string {
  const out: string[] = [pc.bold("Plan")];
  for (const { finding: f, action, reason } of plan) {
    const d = f.dependency;
    const cves = f.vulns.length;
    const head = `${pc.bold(d.name)} ${d.version}${f.safeVersion ? ` → ${f.safeVersion}` : ""}`;
    if (action === "skip") {
      out.push(`  ${pc.yellow("skip    ")} ${head}  ${pc.dim(reason ?? "")}`);
      continue;
    }
    const notes = [`${cves} vuln${cves === 1 ? "" : "s"}`, f.reachability];
    if (f.breaking) notes.push(pc.yellow("breaking: model may edit your code"));
    if (action === "override") notes.push(`via overrides, pulled in by ${d.introducedBy.join(", ")}`);
    out.push(`  ${pc.green(action.padEnd(8))} ${head}  ${pc.dim(notes.join(", "))}`);
  }
  out.push(pc.dim(`  verify with: ${checks.length ? checks.join(" → ") : "(none found)"}`));
  out.push(pc.dim("  Nothing is downgraded. Failed fixes are rolled back."));
  return out.join("\n");
}

export function formatFixSummary(results: FixResult[], remaining: Finding[]): string {
  const out: string[] = [pc.bold("\nFix summary")];
  for (const r of results) {
    const target = r.to ? ` → ${r.to}` : "";
    out.push(`${STATUS_LABEL[r.status]}  ${pc.bold(r.package)} ${r.from}${target}  ${pc.dim(r.strategy)}`);
    if (r.reason) out.push(`  ${pc.dim(r.reason)}`);
    if (r.attempts) out.push(`  ${pc.dim(`model repair rounds: ${r.attempts}, cost: $${r.costUsd.toFixed(4)}`)}`);
    for (const e of r.explanations) out.push(`  ${pc.cyan("model:")} ${e}`);
    if (r.status === "fixed" && r.changedFiles.length) out.push(`  ${pc.dim(`changed: ${r.changedFiles.join(", ")}`)}`);
  }
  const left = remaining.reduce((n, f) => n + f.vulns.length, 0);
  out.push("");
  out.push(left ? pc.yellow(`${left} known vulnerabilities remain in ${remaining.length} packages.`) : pc.green("Rescan is clean."));
  out.push(pc.dim("Changes are left in the working tree for review."));
  return out.join("\n");
}

const REACH_LABEL: Record<Reachability, string> = {
  likely: pc.red("LIKELY REACHABLE"),
  imported: pc.yellow("imported"),
  "not-imported": pc.dim("not imported by your code"),
};

function severityColor(sev: string | undefined): (s: string) => string {
  switch (sev?.toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return pc.red;
    case "MODERATE":
    case "MEDIUM":
      return pc.yellow;
    default:
      return pc.dim;
  }
}

export function formatReport(findings: Finding[], maxUsages = 10): string {
  if (findings.length === 0) return pc.green("No known vulnerabilities found.");
  const out: string[] = [];
  const vulnCount = findings.reduce((n, f) => n + f.vulns.length, 0);
  out.push(pc.bold(`Found ${vulnCount} vulnerabilities in ${findings.length} packages\n`));

  for (const f of findings) {
    const d = f.dependency;
    const kind = d.direct ? "direct" : `transitive via ${d.introducedBy.join(", ") || "?"}`;
    out.push(`${pc.bold(`${d.name}@${d.version}`)}  ${pc.dim(`(${kind}${d.dev ? ", dev" : ""})`)}  ${REACH_LABEL[f.reachability]}`);

    for (const v of f.vulns) {
      const cves = v.aliases.filter((a) => a.startsWith("CVE-"));
      const sev = severityColor(v.severity)(`[${v.severity ?? "UNKNOWN"}]`);
      out.push(`  ${sev} ${v.id}${cves.length ? ` (${cves.join(", ")})` : ""}  ${v.summary}`);
      for (const c of v.fixCommits.slice(0, 2)) out.push(pc.dim(`      fix: ${c}`));
    }

    if (f.safeVersion) {
      const note = f.breaking ? pc.yellow("  (breaking upgrade, may need code changes)") : "";
      out.push(`  ${pc.green("→ safe version:")} ${f.safeVersion}${note}`);
    } else {
      out.push(`  ${pc.red("→ no safe version available; backport needed")}`);
    }

    if (f.usages.length) {
      out.push(`  ${pc.cyan(`used in ${f.usages.length} place(s):`)}`);
      for (const u of f.usages.slice(0, maxUsages)) {
        const flag = u.mentionedBy.length ? pc.red(` ← named in ${u.mentionedBy.join(", ")}`) : "";
        out.push(`    ${u.file}:${u.line}:${u.column}  ${pc.bold(u.symbol)}  ${pc.dim(u.snippet)}${flag}`);
      }
      if (f.usages.length > maxUsages) out.push(pc.dim(`    … ${f.usages.length - maxUsages} more`));
    }
    out.push("");
  }
  return out.join("\n");
}
