import pc from "picocolors";
import { epssLabel } from "./epss.js";
import type { FixResult, FixStatus, PlanStep } from "./fix/upgrade.js";
import type { Finding, Reachability, Triage } from "./types.js";

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
    const target = action === "backport" ? " (stays, patched)" : f.safeVersion ? ` → ${f.safeVersion}` : "";
    const head = `${pc.bold(d.name)} ${d.version}${target}`;
    if (action === "skip") {
      out.push(`  ${pc.yellow("skip    ")} ${head}  ${pc.dim(reason ?? "")}`);
      continue;
    }
    const notes = [`${cves} vuln${cves === 1 ? "" : "s"}`, f.reachability];
    if (f.unfixable.length && action !== "backport") notes.push(`${f.unfixable.length} without a fixed release stay open`);
    if (f.breaking && action === "upgrade") notes.push(pc.yellow("breaking: model may edit your code"));
    if (action === "override") notes.push(`via overrides, pulled in by ${d.introducedBy.join(", ")}`);
    if (action === "backport") notes.push(`${reason}: port upstream fix into ${d.version}, prove it with a PoC, keep it via postinstall`);
    out.push(`  ${pc.green(action.padEnd(8))} ${head}  ${pc.dim(notes.join(", "))}`);
  }
  out.push(pc.dim(`  verify with: ${checks.length ? checks.join(" → ") : "(none found)"}`));
  out.push(pc.dim("  Nothing is downgraded. Failed fixes are rolled back."));
  return out.join("\n");
}

export function formatFixSummary(results: FixResult[], remaining: Finding[]): string {
  const out: string[] = [pc.bold("\nFix summary")];
  for (const r of results) {
    const target = r.strategy === "backport" ? " (patched in place)" : r.to ? ` → ${r.to}` : "";
    out.push(`${STATUS_LABEL[r.status]}  ${pc.bold(r.package)} ${r.from}${target}  ${pc.dim(r.strategy)}`);
    if (r.reason) out.push(`  ${pc.dim(r.reason)}`);
    if (r.attempts) out.push(`  ${pc.dim(`model repair rounds: ${r.attempts}, cost: $${r.costUsd.toFixed(4)}`)}`);
    for (const e of r.explanations) out.push(`  ${pc.cyan("model:")} ${e}`);
    if (r.status === "fixed" && r.changedFiles.length) out.push(`  ${pc.dim(`changed: ${r.changedFiles.join(", ")}`)}`);
  }
  const left = remaining.reduce((n, f) => n + f.vulns.length, 0);
  out.push("");
  out.push(left ? pc.yellow(`${left} known vulnerabilities remain in ${remaining.length} packages.`) : pc.green("Rescan is clean."));
  return out.join("\n");
}

const REACH_LABEL: Record<Reachability, string> = {
  likely: pc.red("LIKELY REACHABLE"),
  imported: pc.yellow("imported"),
  "not-imported": pc.dim("not imported by your code"),
};

const TRIAGE_LABEL: Record<Triage["verdict"], string> = {
  reachable: pc.red("triage: REACHABLE —"),
  "not-reachable": pc.green("triage: not reachable —"),
  unclear: pc.yellow("triage: unclear —"),
};

/** e.g. `1 critical, 13 high, 15 moderate, 2 low`, most severe first; unrated ones last. */
export function severityBreakdown(findings: Finding[]): string {
  const order = ["CRITICAL", "HIGH", "MODERATE", "LOW", "UNRATED"];
  const counts = new Map<string, number>();
  for (const v of findings.flatMap((f) => f.vulns)) {
    const raw = v.severity?.toUpperCase() ?? "UNRATED";
    const sev = raw === "MEDIUM" ? "MODERATE" : order.includes(raw) ? raw : "UNRATED";
    counts.set(sev, (counts.get(sev) ?? 0) + 1);
  }
  return order.filter((s) => counts.has(s)).map((s) => `${counts.get(s)} ${s.toLowerCase()}`).join(", ");
}

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

/** `codeAnalysed` is false for an SBOM, where there is no source to tell whether a package is used. */
export function formatReport(findings: Finding[], maxUsages = 10, codeAnalysed = true): string {
  if (findings.length === 0) return pc.green("No known vulnerabilities found.");
  const out: string[] = [];
  const vulnCount = findings.reduce((n, f) => n + f.vulns.length, 0);
  out.push(pc.bold(`Found ${vulnCount} vulnerabilities in ${findings.length} packages`) + pc.dim(` (${severityBreakdown(findings)})\n`));

  for (const f of findings) {
    const d = f.dependency;
    // go.mod and Pipfile.lock do not record which package pulls in an indirect one.
    const kind = d.binaries
      ? d.binaries.length === 1 && d.binaries[0].name === d.name
        ? `${d.ecosystem} package`
        : `${d.ecosystem} source package, installed as ${d.binaries.map((b) => b.name).join(", ")}`
      : d.direct
        ? "direct"
        : d.introducedBy.length
          ? `transitive via ${d.introducedBy.join(", ")}`
          : "transitive";
    out.push(`${pc.bold(`${d.name}@${d.version}`)}  ${pc.dim(`(${kind}${d.dev ? ", dev" : ""})`)}  ${codeAnalysed ? REACH_LABEL[f.reachability] : pc.dim("reachability unknown (no source code)")}`);
    if (f.triage) {
      out.push(`  ${TRIAGE_LABEL[f.triage.verdict]} ${f.triage.reasoning}`);
      out.push(pc.dim(`    exploitable if: ${f.triage.conditions}`));
    }

    for (const v of f.vulns) {
      const cves = v.aliases.filter((a) => a.startsWith("CVE-"));
      const sev = severityColor(v.severity)(`[${v.severity ?? "UNKNOWN"}]`);
      const kev = v.knownExploited ? ` ${pc.bgRed(pc.white(" KNOWN EXPLOITED "))}` : "";
      const epss = epssLabel(v) ? ` ${pc.magenta(epssLabel(v))}` : "";
      out.push(`  ${sev}${kev}${epss} ${v.id}${cves.length ? ` (${cves.join(", ")})` : ""}  ${v.summary}`);
      for (const c of v.fixCommits.slice(0, 2)) out.push(pc.dim(`      fix: ${c}`));
    }

    if (f.safeVersion) {
      const note = f.breaking ? pc.yellow("  (breaking upgrade, may need code changes)") : "";
      const label = f.unfixable.length ? `→ upgrade fixes ${f.vulns.length - f.unfixable.length} of ${f.vulns.length}:` : "→ safe version:";
      out.push(`  ${pc.green(label)} ${f.safeVersion}${note}`);
    }
    if (f.unfixable.length) {
      out.push(`  ${pc.red("→ no fixed release yet:")} ${f.unfixable.join(", ")}`);
    }

    if (f.usages.length) {
      out.push(`  ${pc.cyan(`used in ${f.usages.length} place(s):`)}`);
      for (const u of f.usages.slice(0, maxUsages)) {
        const flag = u.mentionedBy.length ? pc.red(` ← named in ${u.mentionedBy.join(", ")}`) : "";
        out.push(`    ${u.file}:${u.line}:${u.column}  ${pc.bold(u.symbol)}  ${pc.dim(u.snippet)}${flag}`);
      }
      if (f.usages.length > maxUsages) out.push(pc.dim(`    … ${f.usages.length - maxUsages} more`));
    }
    if (f.mitigation) {
      out.push(`  ${pc.cyan("mitigated at call sites")} (${f.mitigation.files.join(", ")}): ${f.mitigation.explanation}`);
      out.push(pc.dim(`    still exploitable: ${f.mitigation.residualRisk}`));
    }
    for (const via of f.via) {
      out.push(`  ${pc.cyan(`reached through ${via.package}, used in ${via.usages.length} place(s):`)}`);
      for (const u of via.usages.slice(0, 3)) out.push(`    ${u.file}:${u.line}:${u.column}  ${pc.bold(u.symbol)}  ${pc.dim(u.snippet)}`);
      if (via.usages.length > 3) out.push(pc.dim(`    … ${via.usages.length - 3} more`));
    }
    out.push("");
  }
  return out.join("\n");
}
