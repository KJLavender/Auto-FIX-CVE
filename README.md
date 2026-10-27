# Auto-FIX-CVE

**English** | [繁體中文](README.zh-TW.md)

Most dependency scanners stop at "upgrade to vX". Auto-FIX-CVE closes the loop. It finds the CVE and locates the exact lines in **your** code that use the vulnerable API. Then it fixes the problem in one of two ways: upgrade and repair the code that breaks, or, when you can't upgrade, backport the upstream patch into the version you have. Every fix is verified, and anything that fails verification is rolled back.

On eight real security upgrades that break code (marked, PyJWT, urllib3, Werkzeug and others, across npm, uv, Poetry and Pipenv), it fixed all 57 vulnerabilities with the projects' tests still passing. The six code repairs took one model round each, for about $0.12 in total ([benchmark](#benchmark)).

> Status: early development. Support matrix:

| Ecosystem | Lockfiles | Scan + reachability | Fix (upgrade + LLM repair) | Transitive fix | Backport |
|---|---|---|---|---|---|
| JavaScript / TypeScript | npm, pnpm (v6–v9, multi-doc), Yarn classic + Berry | AST import analysis | npm, pnpm, Yarn | npm / pnpm exact-version overrides | npm |
| Python | uv, Poetry, Pipenv, pinned `requirements.txt` | import analysis, `PyYAML` → `yaml` mapping | uv, Poetry, Pipenv | uv constraints | — |
| Go | `go.mod` | import analysis + advisory's vulnerable-function list | `go.mod` + `go mod tidy` | yes (explicit require) | — |
| Rust | `Cargo.lock` | `use` analysis + RustSec function list | `Cargo.toml` + `cargo update` | `cargo update --precise` | — |
| .NET (C#) | `packages.lock.json`, `obj/project.assets.json` | `using` / qualified-name analysis | `.csproj` or `Directory.Packages.props` + `dotnet restore` | direct `PackageReference` pin | — |

## How it works

```
1. Scan        package-lock.json → OSV.dev → CVEs, fixed versions, fix commits
2. Impact      AST analysis finds every import / call of the vulnerable package
3. Plan        upgrade, override (transitive), backport or skip; you confirm first
4. Fix         A) upgrade; if your checks fail, the LLM repairs the call sites
               B) backport: port the upstream fix commit into the installed version
5. Verify      your checks pass, rescan is clean, and for backports a PoC that
               reproduced the bug before the patch passes after it
```

What sets it apart:

- **The safe version really is safe, and installable.** Every suggested upgrade target is re-checked against OSV, so an upgrade never lands on a different CVE. It also skips releases that are yanked (PyPI, crates.io) or deprecated (npm). For example, lodash 4.18.0 fixes the CVEs but is deprecated as a "bad release", so 4.18.1 is suggested instead.
- **Reachability hints.** Each finding is labelled `LIKELY REACHABLE`, `imported` or `not imported`. A usage is flagged when the API it calls (e.g. `_.template`) is named in the advisory. When the advisory lists its vulnerable functions, as Go and RustSec advisories do, that list is used instead of the prose. Transitive packages are traced to the direct dependency you call: `qs` inside `express` shows the line where you use `express`.
- **Backports that are proven, not assumed.** A backport is kept only if a PoC reproduces the vulnerability on the unpatched package, passes on the patched one, and still passes after a clean reinstall.
- **No new dependencies to fix old ones.** Backports are re-applied by a small, dependency-free postinstall script that is committed to your repo. In testing, adding `patch-package` for this pulled in a vulnerable transitive dependency of its own.

## Usage

Requires Node.js ≥ 22.12 and a lockfile: `package-lock.json` / `npm-shrinkwrap.json` (v2/v3), `pnpm-lock.yaml` (v6–v9) or `yarn.lock` (v1 or Berry). For Python: `uv.lock`, `poetry.lock`, `Pipfile.lock` or a pinned `requirements.txt` (pip-compile / `uv export` `# via` comments are used to rebuild the dependency graph). For Go: `go.mod`. For Rust: `Cargo.lock`. For .NET: `packages.lock.json`, or `obj/project.assets.json`, which every `dotnet restore` writes, so projects without a NuGet lockfile work too (packages with `PrivateAssets="all"`, such as analyzers, count as build-only). `fix` works with every lockfile above except a plain `requirements.txt`. For Go it raises the requirement in `go.mod` (indirect ones too), runs `go mod tidy`, and verifies with `go build ./...` and `go test ./...`. For Rust it rewrites the requirement in `Cargo.toml` (exact `=` pins stay exact) or, for a transitive crate, runs `cargo update -p crate@old --precise new`, which cargo refuses if another crate's requirement would break; then `cargo build` and `cargo test`. For .NET it raises the `PackageReference` version in the project file (or the `PackageVersion` in `Directory.Packages.props` under Central Package Management), pins a transitive package by referencing it directly at the fixed version, runs `dotnet restore` (with `--force-evaluate` when there is a lockfile), and verifies with `dotnet build`, plus `dotnet test` for test projects. C# reachability is by namespace: `using` directives, aliases and fully qualified names. `fix` also needs a local LLM CLI (see [LLM backend](#llm-backend)).

Run it straight from GitHub, no install needed:

```bash
npx github:KJLavender/Auto-FIX-CVE scan path/to/project
```

Or from a clone (the examples below use this form):

```bash
npm install                                 # also builds dist/
node dist/cli.js scan   path/to/project     # report CVEs and where your code uses them
node dist/cli.js fix    path/to/project     # plan, confirm, fix, verify
node dist/cli.js verify path/to/project     # re-run backport PoCs (for CI)
node dist/cli.js doctor                     # which package managers / tools are available
```

`scan` only needs network access to OSV. `fix` drives the project's own package manager and the LLM CLI; `doctor` lists what is installed and what each tool enables.

### Scan

```bash
node dist/cli.js scan path/to/project --json      # machine-readable
node dist/cli.js scan path/to/project --no-dev    # skip dev-only deps
node dist/cli.js scan path/to/repo -r             # every project in a monorepo
node dist/cli.js scan path/to/project --min-severity high   # hide low and moderate
```

A directory with both a JavaScript and a Python lockfile gets both scanned. `--recursive` walks subdirectories (skipping `node_modules`, virtualenvs and build output), prints one section per project, and merges everything into one SARIF report.

Exit codes: `0` no vulnerabilities, `1` vulnerabilities found, `2` error.

Example (from `test/fixtures/vuln-app`):

```
lodash@4.17.20  (direct)  LIKELY REACHABLE
  [HIGH] GHSA-35jh-r3h4-6jhm (CVE-2021-23337)  Command Injection in lodash
      fix: https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c
  → safe version: 4.18.1
  used in 2 place(s):
    src/render.ts:5:20  template  const compiled = _.template(userTemplate); ← named in GHSA-35jh-r3h4-6jhm, ...
    src/render.ts:6:19  merge     return compiled(merge({}, data));

minimist@1.2.5  (direct)  not imported by your code
  [CRITICAL] GHSA-xvch-5gv4-984h (CVE-2021-44906)  Prototype Pollution in minimist
  → safe version: 1.2.6
```

#### LLM triage

```bash
node dist/cli.js scan path/to/project --triage                 # judge up to 10 packages
node dist/cli.js scan path/to/project --triage --max-cost 0.20  # with a spending cap
node dist/cli.js scan path/to/project --triage --fail-on likely
```

For every vulnerable package your code actually uses, the model reads the advisories and the numbered code around each call site (including calls into the direct dependency that pulls a transitive package in) and returns `reachable`, `not reachable` or `unclear`, the reasoning, and the conditions under which it would be exploitable:

```
requests@2.25.0  (direct)  LIKELY REACHABLE
  triage: unclear — ... The .netrc leak could apply, since requests.get reads .netrc by default and `url` may be attacker-influenced ...
idna@2.10  (transitive via requests)  imported
  triage: REACHABLE — fetch(url) calls requests.get(url), which encodes non-ASCII hostnames with idna.encode() ...
```

`not reachable` is only allowed when the code itself rules out every advisory; anything that depends on the environment or on where an input comes from is `unclear`. With `--fail-on likely`, a `reachable` verdict fails the build, `not reachable` does not, and `unclear` falls back to the name-matching heuristic. In SARIF, `not reachable` alerts are downgraded to notes. Verdicts can differ between runs, so treat them as a review aid. Cost on the Python example: about $0.15 for five packages.

#### Risk-based gate

```bash
node dist/cli.js scan path/to/project --fail-on risk
```

Severity alone blocks too much: a build can be held up for weeks by a HIGH advisory in code you never call, while a MODERATE one that is being attacked right now slips through. `--fail-on risk` fails only on what matters now:

- any vulnerability in CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog (attacked in the wild), whatever its rating, or
- a high or critical one that your code reaches (`likely`, or a `reachable` triage verdict; a `not reachable` verdict clears it).

Known-exploited vulnerabilities are listed first and tagged `KNOWN EXPLOITED` in the report, Markdown and SARIF (where they are always errors). Everything else is still reported, so you can fix it on a schedule instead of on the release path. The catalog is downloaded once per run; see [Mirrors and offline use](#mirrors-and-offline-use) to use a local copy.

Each CVE also gets its [EPSS](https://www.first.org/epss/) score, FIRST's estimate of the probability that it is exploited in the next 30 days. Scores of 1% and up appear next to the advisory (`EPSS 36%`) and in Markdown and SARIF, and findings with the same reachability and severity are ordered by it. `--epss-threshold 0.1` makes `--fail-on risk` also fail on anything scored at 10% or more, which catches a freshly published bug before it reaches the KEV catalog: Node2Shell scored 36% (98th percentile) five days after release.

#### Deployed images (SBOM)

```bash
trivy image --format cyclonedx -o api.cdx.json registry.example.com/shop/api:<deployed-tag>
node dist/cli.js scan . --sbom api.cdx.json --baseline api.baseline.json --fail-on risk
```

A pipeline only checks code when someone pushes. When a new CVE is published, the images already running are not looked at again until the next change. `--sbom` scans a CycloneDX or SPDX JSON SBOM instead of lockfiles: the output of `trivy image`, or the SBOM Harbor generates for an image. Run it on a schedule against the SBOMs of what is deployed, with a baseline, and the job fails only when something **new** appears, such as a package that just landed in the KEV catalog. The npm, PyPI, Go, crates.io and NuGet packages in the SBOM are checked, including which direct dependency pulls each transitive one in. **OS packages** are checked too, for Debian, Ubuntu, Alpine, AlmaLinux and Rocky Linux images, against OSV's advisories for that exact release (`Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.20`, `AlmaLinux:9`, `Rocky Linux:9`), with versions compared the way dpkg, apk and rpm do. Debian, Ubuntu and Alpine advisories are about source packages (`brotli`) while images install binaries built from them (`libbrotli1`), so binaries are grouped under their source package (from Trivy's `SrcName`/`SrcVersion`, or SPDX `sourceInfo`). Other systems (RHEL, Amazon Linux) and package types are counted but not checked; leave those to Trivy.

For networks that install OS packages from an offline mirror, `--os-list <file>` writes one pin per installed binary that an upgrade fixes, in the package manager's own format (`libbrotli1=1.0.9-2+deb12u1` for apt, `libssl3=3.1.8-r1` for apk, `openssl-libs-1:3.5.8-2.el9_8` for dnf), ready to download on a connected machine and upload to the mirror. With no source code, reachability is unknown, so use `--fail-on any`, `high` or `risk` (which then means known-exploited). `.autofix-cve.json` ignore rules in `[dir]` still apply. Combine with `runtime` for the Node.js and .NET runtimes, which SBOMs often miss.

### Accepted risks

Record vulnerabilities you decided not to fix in `.autofix-cve.json`. A reason is required, and an optional expiry date makes the vulnerability come back for review:

```json
{
  "$schema": "https://raw.githubusercontent.com/KJLavender/Auto-FIX-CVE/main/schema/autofix-cve.schema.json",
  "backports": [],
  "ignore": [
    { "id": "CVE-2021-44906", "package": "minimist", "reason": "only parses our own build script arguments", "until": "2027-01-01" }
  ]
}
```

`id` can be a GHSA, PYSEC, GO, RUSTSEC or CVE id. The `$schema` line (added automatically when the tool writes the file) gives editors autocompletion and flags a missing reason or a malformed date. Ignored vulnerabilities are left out of findings, `--fail-on`, SARIF and `fix` (including the upgrade search), and `scan` lists them with their reasons. A rule without a reason, or past its `until` date, is not applied and `scan` says so.

#### VEX for other scanners

```bash
node dist/cli.js scan . --triage --vex app.vex.json
trivy image --vex app.vex.json registry.example.com/shop/api:abc123
```

An allowlist in a registry or scanner says "stop reporting this" without saying why, and entries tend to outlive the reason. `--vex <file>` writes an [OpenVEX](https://openvex.dev) document instead, with one statement per vulnerability that this tool can actually back:

- `not_affected` / `vulnerable_code_not_in_execute_path` for packages the model triaged as **not reachable**, with its reasoning as the impact statement;
- `not_affected` for ignore rules that carry an OpenVEX `justification` (e.g. `"justification": "vulnerable_code_cannot_be_controlled_by_adversary"` next to the `reason`); the rule's `until` date ends the statement too, because an expired rule is not applied;
- `fixed` for verified backports.

Ignore rules without a `justification` only accept the risk locally and make no claim to other tools. Statements name each package by its purl (Debian packages by their installed binaries). `--vex-product <purl>` lists them as subcomponents of a product such as the container image (`pkg:oci/…`), as Trivy expects for images. Keep the file in Git next to the code, so every exception is reviewed like any other change.

### Fix

```bash
node dist/cli.js fix path/to/project --dry-run          # show the plan only
node dist/cli.js fix path/to/project --check "npm test" # custom verification command(s)
node dist/cli.js fix path/to/project --only marked      # one package
node dist/cli.js fix path/to/project --lockfile uv.lock # pick one when JS and Python sit side by side
node dist/cli.js fix path/to/project --no-breaking      # semver-compatible upgrades only
node dist/cli.js fix path/to/project --prefer-backport  # backport instead of breaking upgrades
node dist/cli.js fix path/to/project --no-backport      # never patch installed packages
node dist/cli.js fix path/to/project --yes              # no prompt (CI)
node dist/cli.js fix path/to/project --max-cost 0.50    # stop calling the model after $0.50
node dist/cli.js fix path/to/project --pr               # commit on a new branch and open a GitHub PR
```

`fix` first prints a plan and asks before changing anything:

```
Plan
  skip     axios 0.21.0 → 0.34.0  breaking upgrade with no build/test command to verify it (pass --check); no backport possible
  upgrade  lodash 4.17.20 → 4.18.0  5 vulns, likely
  upgrade  minimist 1.2.5 → 1.2.6  1 vuln, not-imported
  verify with: (none found)
  Nothing is downgraded. Failed fixes are rolled back.
Apply 2 change(s)? [y/N]
```

How it picks an action:

| Situation | Action |
|---|---|
| Fixed version is semver-compatible | **upgrade** (direct) or **override** (transitive, keyed on the exact vulnerable version such as `"qs@6.7.0": "6.16.0"`, so other copies of the package are untouched) |
| Fixed version is breaking, checks exist | **upgrade**, and the LLM repairs code if checks fail |
| Breaking and `--prefer-backport` / `--no-breaking`, or no checks to verify | **backport** |
| Transitive dependency that needs a breaking upgrade | **backport** |
| No fixed release yet, but an upstream fix commit exists | **backport** |
| Upgrade failed after all repair attempts | rolled back, then **backport** |
| No fix commit to port | **skip** |

Safety rules:

- **Never downgrades.** It only moves to the smallest version above the current one that OSV reports as clean.
- **Asks first.** Without a terminal it refuses to run unless you pass `--yes`.
- **Rolls back failures.** `package.json`, the lockfile, every edited file and `node_modules` are restored. This includes the model being unavailable or the `--max-cost` budget running out partway through a fix.
- **Won't hang on prompts.** Child commands run without stdin and with `CI=1`, so anything waiting for a `y` fails instead, and `npx` never downloads packages on its own.
- **Refuses a dirty git tree** (override with `--allow-dirty`) so the result is easy to review with `git diff`.

#### Upgrade path

1. Confirms your checks (typecheck/build/test scripts, or `--check`) pass **before** touching anything.
2. Upgrades. If the caret range resolves to a newer version, that version is checked against OSV too.
3. If the checks fail, the LLM gets the failing output, the usage sites, the package's runtime exports **before and after** the upgrade, its changelog and the relevant files. It answers with exact search/replace edits.
4. Repeats up to `--max-attempts` (default 3), otherwise rolls back.

For uv projects the same loop edits `pyproject.toml` (a pinned requirement stays pinned, a range gets a floor), constrains transitive packages under `[tool.uv] constraint-dependencies`, runs `uv lock` + `uv sync`, and verifies with `uv run pytest` when the project uses pytest. Poetry projects work the same way, also rewriting Poetry's own `[tool.poetry.*dependencies]` tables in the project's constraint style (`^`, `~`, pins); Pipenv projects get the same treatment for `Pipfile`. Neither Poetry nor Pipenv has an override mechanism, so transitive Python packages there are reported but not changed. Python example (`test/fixtures/python-breaking-app`): Werkzeug 2.2.3 → 3.1.9 fixes 16 CVEs, and the model replaces the removed `werkzeug.urls.url_quote` with `urllib.parse.quote`.

Example (from `test/fixtures/breaking-app`, where marked 4 removed the callable module export):

```
FIXED  marked 2.1.3 → 4.3.0  upgrade
  model repair rounds: 1, cost: $0.0260
  model: marked 4.x no longer exports the module as a function; it exposes a named `marked` export. ...
  changed: package.json, package-lock.json, src/render.js
```

#### Backport path

1. Downloads the fix commits linked from the advisory and separates library changes from upstream tests.
2. **Proves the bug.** The LLM writes a PoC check from the advisory and the upstream tests. It must report *vulnerable* on the installed version, otherwise that CVE is left open and reported.
3. Finds every shipped copy of the vulnerable code (source, CJS and ESM bundles, minified builds) and has the LLM port the fix into each of them.
4. Re-runs every PoC until all pass, then runs your checks.
5. Saves the edits to `.autofix-cve/patches/<pkg>@<version>.json` and adds `node .autofix-cve/apply-patches.cjs` to `postinstall`.
6. Deletes the package, reinstalls, and runs the PoCs again, so the patch is proven to survive `npm install` / `npm ci`.

Example (`fix --prefer-backport` on `test/fixtures/breaking-app`):

```
marked@2.1.3
  backport marked@2.1.3: 2 fix(es) downloaded
  GHSA-5v2h-r2cx-5xgj: reproduced on 2.1.3
  GHSA-rrrm-qjm4-v8hf: reproduced on 2.1.3
  porting the fix (attempt 1/3)
  all 2 PoC(s) pass after patching
  patch re-applied by postinstall and verified after a clean reinstall

FIXED  marked 2.1.3 (patched in place)  backport
  model: Ported the ReDoS fix ... Applied to src/rules.js, lib/marked.esm.js, lib/marked.js and marked.min.js.
Rescan is clean.
```

Files a backport adds to your repo:

```
.autofix-cve.json                         which CVEs are backported, for which exact version
.autofix-cve/apply-patches.cjs            dependency-free postinstall script
.autofix-cve/patches/marked@2.1.3.json    the search/replace edits
.autofix-cve/poc/GHSA-….cjs               the PoCs that proved the fix
```

`scan` treats those CVEs as fixed **only for that exact version and only while the patch is actually applied**. If the package version changes, or an install skipped scripts, the CVEs are reported again.

#### Pull requests

With `--pr`, the fixes are committed to a new `autofix-cve/<timestamp>` branch, pushed, and opened as a pull request: with `gh` when `origin` is on GitHub, and as a **merge request through the REST API** for any other host, which is treated as GitLab (self-hosted included). Prerequisites are checked before anything runs: a checked-out branch, an `origin` remote, and either a logged-in `gh` or a GitLab token with `api` scope in `AUTOFIX_GITLAB_TOKEN`. The generic `GITLAB_TOKEN` is also accepted, but only sent to the host it is meant for (`GITLAB_HOST`, as with `glab`, or gitlab.com), so a token for one instance never leaks to another. The API root comes from the remote, from `CI_API_V4_URL` inside GitLab CI, or from `AUTOFIX_GITLAB_API`. The PR body lists every fixed CVE with its evidence (checks that passed, PoC verdicts, OSV confirmation), the model's explanation of each code change, anything that was not fixed and why, and the rescan result. If nothing could be fixed, the branch is deleted.

### Runtime (Dockerfiles)

```bash
node dist/cli.js runtime path/to/repo                  # report
node dist/cli.js runtime path/to/repo --fix            # pin the base images
node dist/cli.js runtime path/to/repo --fail-on risk --json
```

Some of the worst vulnerabilities are not in any package: Node2Shell (CVE-2026-111497) is an out-of-bounds write in the Brotli decoder **built into Node.js**, and the same upstream bug was fixed in .NET 8.0.33. A lockfile scan cannot see them, and neither can `apt-get upgrade`, because the official images do not install the runtime as an OS package. `runtime` reads every Dockerfile (subdirectories included) and checks the Node.js and .NET images it builds on:

- **Pinned tags** (`node:22.20.0-slim`, `dotnet/aspnet:8.0.30`): the vulnerabilities fixed in later releases of the same line. Node.js uses the Node.js security team's advisory index, and also any newer release marked as a security release that the index has not caught up with yet, which is how Node2Shell shows up on the day of the release. .NET uses the CVE list in Microsoft's release metadata.
- **Floating tags** (`node:22-bookworm-slim`, `aspnet:8.0`): the version depends on what the registry, or a mirror's cache, served at build time, so a rebuild may not pick up a fix. They are reported and pinned.
- **End of support** within 90 days, or already past.
- Build stages that do not ship are reported but never fail the build. `FROM` lines and `ARG` defaults are both understood, and registry prefixes (`nexus:8443/library/node`) are fine.

`--fix` rewrites each affected `FROM` (or the `ARG` it takes the version from) to the newest release of the same line, keeping the variant (`-bookworm-slim`, `-noble-chiseled`). It never changes the major version. A `@sha256` digest is dropped with a note, since the new one is only known after pulling. Rebuild and redeploy afterwards.

### Mitigate (no fixed release yet)

```bash
node dist/cli.js mitigate path/to/project
```

Sometimes there is nothing to upgrade to: `xlsx` 0.18.5 on npm has a prototype pollution and a ReDoS advisory, and the fixed versions were never published to npm. `mitigate` takes each vulnerability without a fixed release that your code calls into, shows the model the advisories and **your own call sites**, and asks for guards there: input validation, size caps, stripping dangerous keys, or a safer option of the same API. The guards are applied, your checks are run, and anything that fails is rolled back (with another round that sees the failure). Dependency manifests, lockfiles and installed packages are never edited, and the model may answer that no guard applies.

On the `xlsx` example (one round, $0.04) it wrapped `XLSX.read` in `parseUpload` with a type and 10 MB size check plus a snapshot of `Object.prototype` that reverts and rejects any pollution, and stated what is still exploitable: a small crafted file can still trigger the ReDoS within the cap, so parse in a worker with a timeout, or move to SheetJS 0.20.2 from its CDN.

A mitigation is recorded in `.autofix-cve.json` with the code it added. The vulnerabilities stay in every report, marked `mitigated at call sites` with the remaining risk, for as long as that code is still there (edit it away and the mark goes too). `scan --vex` states them as `not_affected` / `inline_mitigations_already_exist`. Upgrade with `fix` as soon as a fixed release ships.

### Audit (everything at once)

```bash
node dist/cli.js audit . --sbom api.cdx.json
```

`audit` scans every lockfile below the directory, the Node.js and .NET runtimes in its Dockerfiles, and any SBOMs given, then puts **one vulnerability that shows up in several components** at the top, each with its own fix:

```
CVE-2026-111497  src: expose `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`
  brotli 1.0.9-2 (libbrotli1)  image.cdx.json        → brotli 1.0.9-2+deb12u1
  Node.js 22.20.0              api/Dockerfile:1      → FROM node:22.23.4-bookworm-slim
  .NET 8.0.30                  backend/Dockerfile:1  → FROM mcr.microsoft.com/dotnet/aspnet:8.0.33
```

That is Node2Shell: one upstream Brotli bug, bundled into Node.js, into .NET and into Debian's `libbrotli1`. Upgrading one of them leaves the others exposed, and no single scanner shows all three. Records are matched on CVE ids, including the CVEs a Debian advisory names, and for a Node.js security release the advisory index has not caught up with, the CVEs come from the release's changelog. A one-line summary per source follows. `--json` gives the whole result; `--fail-on any|high|risk` turns it into a gate (default: report only).

### Verify (CI)

```bash
node dist/cli.js verify path/to/project
```

Re-runs every stored PoC and exits `1` if any vulnerability is back, for example after an install with `--ignore-scripts`.

```
VULNERABLE  marked@2.1.3  .autofix-cve/poc/GHSA-5v2h-r2cx-5xgj.cjs
[autofix-cve] command timed out after 10s
```

### GitHub Action

```yaml
name: CVE scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # for the SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 22
      - run: npm ci            # applies backports via postinstall, needed by verify
      - uses: KJLavender/Auto-FIX-CVE@main
        with:
          fail-on: likely      # any | likely | high | risk | none
```

The action scans, writes a Markdown table to the job summary, uploads a SARIF report to code scanning, and runs `verify` when the project has backports. Alerts appear on the lockfile entry **and on the exact lines that call the API named in the advisory**. Inputs: `path`, `recursive`, `baseline`, `min-severity`, `fail-on`, `include-dev`, `sarif-file`, `upload-sarif`, `verify`.

The same options are available locally:

```bash
node dist/cli.js scan . --sarif results.sarif --markdown summary.md --fail-on likely
```

Adopting it on an old project? Record what is already there, and let only new vulnerabilities fail the build. Known ones stay visible in the report:

```bash
node dist/cli.js scan . --baseline .autofix-baseline.json --update-baseline   # once, commit the file
node dist/cli.js scan . --baseline .autofix-baseline.json                     # in CI
```

## Benchmark

Eight real security upgrades that break or could break code, each a tiny project with tests (`bench/cases`). `npm run bench` copies each one to a temp dir, runs `fix --yes`, and measures the result:

| Case | Upgrade | Vulns before → after | Result | Model rounds | Source lines changed | Cost | Time |
|---|---|---|---|---|---|---|---|
| js-jsonwebtoken | jsonwebtoken 8.5.1 → 9.0.0 | 3 → 0 | fixed | 0 | none | $0.000 | 6s |
| js-marked | marked 2.1.3 → 4.3.0 | 2 → 0 | fixed | 1 | +1 −1 | $0.015 | 11s |
| js-xml2js | xml2js 0.4.23 → 0.5.0 | 1 → 0 | fixed | 0 | none | $0.000 | 4s |
| py-poetry-pyjwt | pyjwt 1.7.1 → 2.15.1, pytest 8.4.2 → 9.1.1 | 12 → 0 | fixed, fixed | 1 | +2 −2 | $0.025 | 36s |
| py-pipenv-urllib3 | urllib3 1.26.5 → 2.8.0 | 10 → 0 | fixed | 1 | +1 −1 | $0.019 | 23s |
| py-pyjwt | pyjwt 1.7.1 → 2.15.0 | 11 → 0 | fixed | 1 | +2 −2 | $0.024 | 13s |
| py-urllib3 | urllib3 1.26.5 → 2.8.0 | 10 → 0 | fixed | 1 | +1 −1 | $0.018 | 13s |
| py-werkzeug | werkzeug 2.2.3 → 3.1.9 | 8 → 0 | fixed | 1 | +2 −2 | $0.017 | 13s |

All 57 known vulnerabilities were fixed and every project's tests still pass. Six upgrades broke the code and were repaired by the model in one round, changing one or two lines each: marked's removed callable export, PyJWT 2's required `algorithms` and `str` tokens, urllib3 2's `method_whitelist` → `allowed_methods` (under uv and Pipenv), Werkzeug 3's removed `url_quote`. Total model cost was about $0.12. Results are in `bench/RESULTS.md`. Model output varies between runs.

## Security model

Advisory text and upstream diffs are untrusted input to the LLM, so its output is constrained:

- Code edits are exact search/replace operations. They cannot touch `package.json`, lockfiles or anything outside the project, and backport edits stay inside the one package being patched.
- PoC scripts run under the Node.js permission model (`--permission`): read-only access to the project, no file writes, no child processes, no native addons, and a 10 s timeout.
- Nothing is kept unless your checks pass, and for backports the PoCs too.

## Mirrors and offline use

Every outside service can be pointed at a mirror, for networks that only reach the internet through a proxy such as Nexus:

| Variable | Default | |
|---|---|---|
| `AUTOFIX_OSV_URL` | `https://api.osv.dev/v1` | OSV API (advisories) |
| `AUTOFIX_NPM_REGISTRY` | `npm_config_registry`, else `https://registry.npmjs.org` | npm registry, for skipping deprecated releases |
| `AUTOFIX_PYPI_URL` | `https://pypi.org/pypi` | PyPI JSON API, for skipping yanked releases |
| `AUTOFIX_CRATES_INDEX` | `https://index.crates.io` | crates.io sparse index |
| `AUTOFIX_GITHUB_API` | `https://api.github.com` | GitHub API (GitHub Enterprise), for backport diffs |
| `AUTOFIX_EPSS_URL` | `https://api.first.org/data/v1/epss` | EPSS scores: the API, a local JSON file in its shape, or `off` |
| `AUTOFIX_KEV_URL` | CISA's feed | KEV catalog: a URL, a local JSON file, or `off` |
| `AUTOFIX_NODE_RELEASES_URL` | `https://nodejs.org/dist/index.json` | Node.js releases (`runtime`) |
| `AUTOFIX_NODE_VULNS_URL` | Node.js security-wg `vuln/core/index.json` | Node.js advisory index (`runtime`) |
| `AUTOFIX_NODE_CHANGELOG_URL` | Node.js `doc/changelogs/CHANGELOG_V{major}.md` | CVEs of security releases not yet in the index (`runtime`) |
| `AUTOFIX_NODE_SCHEDULE_URL` | Node.js Release `schedule.json` | Node.js end-of-life dates (`runtime`) |
| `AUTOFIX_DOTNET_RELEASES_URL` | Microsoft's `release-metadata/{channel}/releases.json` | .NET releases; `{channel}` becomes e.g. `8.0` (`runtime`) |

When run through npm or npx, the registry from your `.npmrc` is used automatically. If a registry cannot be reached, the tool still works; it just cannot rule out deprecated or yanked versions.

## LLM backend

The LLM is called through a local CLI in headless mode (`-p --output-format json --json-schema …`) with tools, settings and session history disabled. That means it runs on your existing subscription and needs no API key. Configuration:

| Variable | Default | |
|---|---|---|
| `AUTOFIX_MODEL` | Sonnet 5.5 | model id |
| `AUTOFIX_EFFORT` | `medium` | reasoning effort |
| `AUTOFIX_LLM_BIN` | CLI on `PATH` | path to the CLI executable |
| `AUTOFIX_POETRY` | `poetry` | Poetry command, e.g. `uvx poetry` |
| `AUTOFIX_PIPENV` | `pipenv` | Pipenv command, e.g. `uvx pipenv` |
| `AUTOFIX_PNPM` / `AUTOFIX_YARN` | `pnpm` / `yarn` | pnpm / Yarn command, e.g. `npx pnpm@9` |

Typical cost in the examples above: $0.02–0.03 per upgrade repair, about $0.07 per backport (two PoCs plus the port).

#### OpenAI-compatible endpoints

Where a local CLI is not an option, for example a company LLM gateway in CI, set `AUTOFIX_LLM=openai` to call any OpenAI-compatible `/chat/completions` endpoint instead:

| Variable | Default | |
|---|---|---|
| `AUTOFIX_LLM` | `cli` | `cli` or `openai` |
| `AUTOFIX_OPENAI_BASE_URL` | (required) | e.g. `https://gateway.example.com/v1` |
| `AUTOFIX_OPENAI_API_KEY` | none | sent as `Authorization: Bearer …` |
| `AUTOFIX_MODEL` | (required) | a model the endpoint serves |
| `AUTOFIX_OPENAI_JSON` | `json_schema` | `json_schema`, `json_object`, or `none` when the gateway does not support `response_format`; the schema then goes into the instructions |
| `AUTOFIX_PRICE_INPUT` / `AUTOFIX_PRICE_OUTPUT` | `0` | USD per million tokens, so `--max-cost` can count spending |

Replies are parsed even when wrapped in Markdown fences or text, and a reply that is not valid JSON, or lacks a required field, gets one corrective retry before the fix fails and rolls back. `doctor` checks that the endpoint answers with the configured key.

## FAQ

**Will it upgrade or downgrade packages on its own?** It never downgrades: a target version must be higher than the installed one or the package is skipped. It does not upgrade without asking either. `fix` prints a plan (upgrade, override, backport or skip, with reasons) and waits for `y`. Outside a terminal it refuses to run unless you pass `--yes`. `scan` never changes anything.

**What if an upgrade breaks my code?** Your checks run before anything changes, so a failure that was already there is not blamed on the upgrade. After the upgrade, failing checks go to the LLM, which edits the call sites (up to `--max-attempts`, default 3). If they still fail, everything is rolled back: manifest, lockfile, edited files and installed packages. A breaking upgrade is never attempted without checks to verify it. `--no-breaking` limits fixes to compatible upgrades, and `--prefer-backport` patches the installed version instead (npm).

**Can it hang on a prompt like "Ok to proceed? (y)"?** No. Child commands run without stdin and with `CI=1`, so anything that would wait for input fails instead, and `npx` will not download packages on its own. The only prompt is the plan confirmation.

**Does it need an API key?** No. The LLM runs through a local CLI on your existing subscription (see [LLM backend](#llm-backend)). `scan` needs no LLM at all.

## Development

```bash
npm test            # unit tests (offline)
npm run typecheck
npm run dev -- scan test/fixtures/vuln-app
```

The fixtures under `test/fixtures/` are intentionally vulnerable. Copy them to a temporary directory before running `fix`, because it modifies the project in place.

## Roadmap

- [x] npm lockfile parsing with dependency provenance
- [x] OSV lookup, safe-version search, fix-commit extraction
- [x] AST-based usage analysis (ESM, CommonJS, dynamic import, re-exports)
- [x] Upgrade path with LLM repair and rollback
- [x] Backport path with PoC proof, dependency-free persistence and `verify`
- [x] PR generation with the evidence attached
- [x] GitHub Action with SARIF upload (code scanning alerts on call sites)
- [x] Scan pnpm and Yarn lockfiles
- [x] Fix pnpm projects (exact-version `pnpm.overrides`) and Yarn projects (declared packages; Yarn resolutions cannot target a single version)
- [x] Scan Python projects: uv, Poetry, Pipenv, requirements.txt; PEP 440 versions; import analysis that maps distributions to modules (`PyYAML` → `yaml`) via the virtualenv's `top_level.txt`
- [x] Fix uv, Poetry and Pipenv projects (upgrade + LLM repair)
- [x] Scan Go modules (`go.mod`, import analysis, the advisory's vulnerable-function list for reachability)
- [x] Fix Go modules (`go.mod` + `go mod tidy`, checked in CI with the Go toolchain)
- [x] Scan and fix Rust crates (`Cargo.lock`, `use` trees, RustSec function lists, `cargo update --precise`; checked in CI with cargo)
- [x] Scan and fix .NET projects (`packages.lock.json` / `project.assets.json`, Central Package Management; checked in CI with dotnet)
- [ ] Python backports. Deliberately not done yet, for two reasons. Python package managers have no post-install hook, so a patch to site-packages would silently disappear on the next `uv sync` / `pip install`. And Python has no built-in permission sandbox like Node's, so running a model-written PoC derived from untrusted advisory text could not be contained to the same standard.

## License

MIT
