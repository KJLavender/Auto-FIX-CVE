# Changelog

All notable changes, newest first. No version has been released yet; everything below is on `main`.

## Unreleased

### Ecosystems
- **.NET**: scan `packages.lock.json` or `obj/project.assets.json` (so projects without a NuGet lockfile work), with NuGet version ordering and C# `using` analysis. Fix by raising `PackageReference` / Central Package Management versions, pinning transitive packages with a direct reference, `dotnet restore`, then `dotnet build` and `dotnet test`.
- **Rust**: scan and fix `Cargo.lock` projects. `Cargo.toml` requirements are raised (exact `=` pins stay exact), transitive crates move with `cargo update --precise`, and `use` trees are analysed for reachability.
- **Go**: scan and fix `go.mod` modules, including indirect requirements and `replace` directives, with `go mod tidy`.
- **Python**: scan uv, Poetry, Pipenv and pinned `requirements.txt` (the graph is rebuilt from `# via` comments). Fix uv, Poetry and Pipenv projects. PEP 440 versions, and import analysis that maps distributions to modules (`PyYAML` → `yaml`).
- **pnpm and Yarn**: scan pnpm v6–v9 (including the multi-document lockfiles of pnpm 11+) and Yarn classic and Berry. Fix both, with exact-version `pnpm.overrides`.
- **Monorepos**: `scan -r` walks subdirectories; JS and Python lockfiles in one directory are both scanned, and `fix --lockfile` picks one.

### Fixing
- Plan first, ask `y/N`, never downgrade; `--yes` for CI, `--dry-run`, `--no-breaking`.
- Upgrade path: verify with the project's own checks, let the LLM repair broken call sites, and roll everything back on failure, including when the model is unavailable or the `--max-cost` budget runs out.
- Backport path (npm): port the upstream fix commit into the installed version, prove it with a PoC that fails before and passes after (run under Node's permission model), and persist it with a dependency-free postinstall script. `verify` re-runs the PoCs in CI.
- Transitive packages are overridden only at their exact vulnerable version, and a nested copy pinned to the old version is overridden too.
- `--pr` commits to a new branch and opens a pull request with the evidence for each fix.

### Security of the run itself
- Project commands (installs, checks, anything that runs package code) get only the environment builds need: tokens and keys are not passed, so a compromised release's install script cannot read them. `AUTOFIX_PASS_ENV` names exceptions; git and gh keep the full environment.
- `--ignore-scripts` on `fix` and `mitigate`; `AUTOFIX_EXEC_WRAPPER` runs project commands inside a sandbox such as `docker run … sh -c`.

### Runtimes and gating
- `mitigate`: for vulnerabilities with no fixed release, the model adds guards at the project's own call sites (validation, size caps, safer options), verified by the checks and rolled back on failure. Recorded with the added code; reports mark them as mitigated with the remaining risk while the code is in place, and VEX states `inline_mitigations_already_exist`.
- `runtime`: checks the Node.js and .NET base images in Dockerfiles (pinned or floating tags, `ARG` defaults, registry prefixes) against Node.js's advisory index and security releases and .NET's release CVE lists, warns about end of support, and `--fix` pins them to the newest release of the same line.
- EPSS scores on every CVE (shown from 1%, used for ordering, in Markdown and SARIF); `--epss-threshold` adds them to `--fail-on risk`.
- `audit`: lockfiles, runtimes and SBOMs in one run, with a CVE that appears in several components (Brotli in Node.js, .NET and Debian) grouped and each fix listed. Node.js security releases the advisory index lacks get their CVEs from the release changelog, and Debian advisories are matched on the CVEs they name (also for KEV).
- `scan --vex`: an OpenVEX document from not-reachable triage verdicts, ignore rules with a `justification`, and verified backports, for `trivy --vex` instead of a registry allowlist.
- OS packages in SBOMs: Debian, Ubuntu, Alpine, AlmaLinux and Rocky Linux, compared like dpkg, apk and rpm, with Debian/Ubuntu/Alpine binaries grouped under their source package. `--os-list` writes the pins to download for an offline mirror in apt, apk or dnf format.
- `scan --sbom`: scan a CycloneDX or SPDX SBOM (from `trivy image` or Harbor) instead of lockfiles, with the dependency graph, so deployed images can be re-checked on a schedule against new advisories.
- `--fail-on risk`: fail only on vulnerabilities in CISA's Known Exploited Vulnerabilities catalog, or high/critical ones that the code reaches. Known-exploited ones are tagged in every output.
- LLM: `AUTOFIX_LLM=openai` calls any OpenAI-compatible endpoint (company gateways, vLLM, Ollama) with structured output, a corrective retry, and token pricing for `--max-cost`.
- `--pr` opens GitLab merge requests (self-hosted included) through the REST API.
- Every outside service (OSV, npm, PyPI, crates.io, GitHub, KEV, runtime release data) can be pointed at a mirror or a local file, for networks behind Nexus or offline.
- Checks run Angular's `ng test` once (`--watch=false`) instead of waiting forever in watch mode.

### Scanning and reporting
- The suggested version is the smallest one OSV reports clean that is also installable: yanked (PyPI, crates.io) and deprecated (npm) releases are skipped. For example, lodash 4.18.0 is deprecated as a bad release, so 4.18.1 is suggested.
- When some vulnerabilities have no fixed release, the ones that do still get fixed, and the rest are listed as open.
- OSV records published under several ids (GHSA and PYSEC for one CVE) are merged instead of counted twice.
- Reachability: call sites named in the advisory, the advisory's own vulnerable-function list when it has one (Go, RustSec), transitive packages traced to the direct dependency you call, and an optional LLM verdict (`--triage`).
- Accepted risks in `.autofix-cve.json`, with a required reason and an optional expiry, plus a JSON schema for editors.
- Baseline mode: only vulnerabilities that are new since the baseline fail the build.
- `--min-severity` hides vulnerabilities rated below a level; unrated advisories are always kept.
- Output: SARIF for GitHub code scanning (alerts on the exact call site), Markdown for job summaries, JSON.

### Tooling
- GitHub Action with SARIF upload, job summary, `verify`, `recursive` and `baseline` inputs.
- `doctor` lists which package managers and tools are available.
- Runs from GitHub without installing: `npx github:KJLavender/Auto-FIX-CVE`.
- Benchmark (`npm run bench`): eight real breaking security upgrades, all 57 vulnerabilities fixed, about $0.12 in model cost.
- CI on Linux and Windows (Node 22 and 24), plus end-to-end fix runs for npm, Go and Rust.
