# Changelog

All notable changes, newest first. No version has been released yet; everything below is on `main`.

## Unreleased

### Ecosystems
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

### Scanning and reporting
- The suggested version is the smallest one OSV reports clean that is also installable: yanked (PyPI, crates.io) and deprecated (npm) releases are skipped. For example, lodash 4.18.0 is deprecated as a bad release, so 4.18.1 is suggested.
- When some vulnerabilities have no fixed release, the ones that do still get fixed, and the rest are listed as open.
- OSV records published under several ids (GHSA and PYSEC for one CVE) are merged instead of counted twice.
- Reachability: call sites named in the advisory, the advisory's own vulnerable-function list when it has one (Go, RustSec), transitive packages traced to the direct dependency you call, and an optional LLM verdict (`--triage`).
- Accepted risks in `.autofix-cve.json`, with a required reason and an optional expiry, plus a JSON schema for editors.
- Baseline mode: only vulnerabilities that are new since the baseline fail the build.
- Output: SARIF for GitHub code scanning (alerts on the exact call site), Markdown for job summaries, JSON.

### Tooling
- GitHub Action with SARIF upload, job summary, `verify`, `recursive` and `baseline` inputs.
- `doctor` lists which package managers and tools are available.
- Runs from GitHub without installing: `npx github:KJLavender/Auto-FIX-CVE`.
- Benchmark (`npm run bench`): eight real breaking security upgrades, all 57 vulnerabilities fixed, about $0.12 in model cost.
- CI on Linux and Windows (Node 22 and 24), plus end-to-end fix runs for npm, Go and Rust.
