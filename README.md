# Auto-FIX-CVE

**English** | [繁體中文](README.zh-TW.md)

Most dependency scanners stop at "upgrade to vX". Auto-FIX-CVE closes the loop. It finds the CVE and locates the exact lines in **your** code that use the vulnerable API. Then it fixes the problem in one of two ways: upgrade and repair the code that breaks, or, when you can't upgrade, backport the upstream patch into the version you have. Every fix is verified, and anything that fails verification is rolled back.

> Status: early development. `scan` supports JavaScript (npm, pnpm, Yarn classic and Berry) and Python (uv, Poetry, Pipenv, pinned `requirements.txt`). `fix` supports npm projects (upgrade, backport, PRs) and uv / Poetry projects (upgrade with LLM repair, PRs).

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

- **The safe version really is safe.** Every suggested upgrade target is re-checked against OSV, so an upgrade never lands on a different CVE.
- **Reachability hints.** Each finding is labelled `LIKELY REACHABLE`, `imported` or `not imported`. A usage is flagged when the API it calls (e.g. `_.template`) is named in the advisory. Transitive packages are traced to the direct dependency you call: `qs` inside `express` shows the line where you use `express`.
- **Backports that are proven, not assumed.** A backport is kept only if a PoC reproduces the vulnerability on the unpatched package, passes on the patched one, and still passes after a clean reinstall.
- **No new dependencies to fix old ones.** Backports are re-applied by a small, dependency-free postinstall script that is committed to your repo. In testing, adding `patch-package` for this pulled in a vulnerable transitive dependency of its own.

## Usage

Requires Node.js ≥ 22.12 and a lockfile: `package-lock.json` / `npm-shrinkwrap.json` (v2/v3), `pnpm-lock.yaml` (v6–v9) or `yarn.lock` (v1 or Berry). For Python: `uv.lock`, `poetry.lock`, `Pipfile.lock` or a pinned `requirements.txt` (pip-compile / `uv export` `# via` comments are used to rebuild the dependency graph). `fix` needs `package-lock.json`, `uv.lock` or `poetry.lock`. `fix` also needs a local LLM CLI (see [LLM backend](#llm-backend)).

```bash
npm install
npm run build
node dist/cli.js scan   path/to/project     # report CVEs and where your code uses them
node dist/cli.js fix    path/to/project     # plan, confirm, fix, verify
node dist/cli.js verify path/to/project     # re-run backport PoCs (for CI)
```

### Scan

```bash
node dist/cli.js scan path/to/project --json      # machine-readable
node dist/cli.js scan path/to/project --no-dev    # skip dev-only deps
node dist/cli.js scan path/to/repo -r             # every project in a monorepo
```

A directory with both a JavaScript and a Python lockfile gets both scanned. `--recursive` walks subdirectories (skipping `node_modules`, virtualenvs and build output), prints one section per project, and merges everything into one SARIF report.

Exit codes: `0` no vulnerabilities, `1` vulnerabilities found, `2` error.

Example (from `test/fixtures/vuln-app`):

```
lodash@4.17.20  (direct)  LIKELY REACHABLE
  [HIGH] GHSA-35jh-r3h4-6jhm (CVE-2021-23337)  Command Injection in lodash
      fix: https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c
  → safe version: 4.18.0
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

### Fix

```bash
node dist/cli.js fix path/to/project --dry-run          # show the plan only
node dist/cli.js fix path/to/project --check "npm test" # custom verification command(s)
node dist/cli.js fix path/to/project --only marked      # one package
node dist/cli.js fix path/to/project --no-breaking      # semver-compatible upgrades only
node dist/cli.js fix path/to/project --prefer-backport  # backport instead of breaking upgrades
node dist/cli.js fix path/to/project --no-backport      # never patch installed packages
node dist/cli.js fix path/to/project --yes              # no prompt (CI)
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
- **Rolls back failures.** `package.json`, the lockfile, every edited file and `node_modules` are restored.
- **Won't hang on prompts.** Child commands run without stdin and with `CI=1`, so anything waiting for a `y` fails instead, and `npx` never downloads packages on its own.
- **Refuses a dirty git tree** (override with `--allow-dirty`) so the result is easy to review with `git diff`.

#### Upgrade path

1. Confirms your checks (typecheck/build/test scripts, or `--check`) pass **before** touching anything.
2. Upgrades. If the caret range resolves to a newer version, that version is checked against OSV too.
3. If the checks fail, the LLM gets the failing output, the usage sites, the package's runtime exports **before and after** the upgrade, its changelog and the relevant files. It answers with exact search/replace edits.
4. Repeats up to `--max-attempts` (default 3), otherwise rolls back.

For uv projects the same loop edits `pyproject.toml` (a pinned requirement stays pinned, a range gets a floor), constrains transitive packages under `[tool.uv] constraint-dependencies`, runs `uv lock` + `uv sync`, and verifies with `uv run pytest` when the project uses pytest. Poetry projects work the same way, also rewriting Poetry's own `[tool.poetry.*dependencies]` tables in the project's constraint style (`^`, `~`, pins); Poetry has no override mechanism, so transitive Python packages under Poetry are reported but not changed. Python example (`test/fixtures/python-breaking-app`): Werkzeug 2.2.3 → 3.1.9 fixes 16 CVEs, and the model replaces the removed `werkzeug.urls.url_quote` with `urllib.parse.quote`.

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

With `--pr`, the fixes are committed to a new `autofix-cve/<timestamp>` branch, pushed, and opened as a pull request with `gh`. Prerequisites are checked before anything runs: a checked-out branch, an `origin` remote on GitHub, and a logged-in `gh`. The PR body lists every fixed CVE with its evidence (checks that passed, PoC verdicts, OSV confirmation), the model's explanation of each code change, anything that was not fixed and why, and the rescan result. If nothing could be fixed, the branch is deleted.

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
          fail-on: likely      # any | likely | high | none
```

The action scans, uploads a SARIF report to code scanning, and runs `verify` when the project has backports. Alerts appear on the lockfile entry **and on the exact lines that call the API named in the advisory**. Inputs: `path`, `recursive`, `fail-on`, `include-dev`, `sarif-file`, `upload-sarif`, `verify`.

The same options are available locally:

```bash
node dist/cli.js scan . --sarif results.sarif --fail-on likely
```

## Benchmark

Seven real security upgrades that break or could break code, each a tiny project with tests (`bench/cases`). `npm run bench` copies each one to a temp dir, runs `fix --yes`, and measures the result:

| Case | Upgrade | Vulns before → after | Result | Model rounds | Source lines changed | Cost | Time |
|---|---|---|---|---|---|---|---|
| js-jsonwebtoken | jsonwebtoken 8.5.1 → 9.0.0 | 3 → 0 | fixed | 0 | none | $0.000 | 6s |
| js-marked | marked 2.1.3 → 4.3.0 | 2 → 0 | fixed | 1 | +1 −1 | $0.015 | 11s |
| js-xml2js | xml2js 0.4.23 → 0.5.0 | 1 → 0 | fixed | 0 | none | $0.000 | 4s |
| py-poetry-pyjwt | pyjwt 1.7.1 → 2.15.1, pytest 8.4.2 → 9.1.1 | 12 → 0 | fixed, fixed | 1 | +2 −2 | $0.025 | 36s |
| py-pyjwt | pyjwt 1.7.1 → 2.15.0 | 11 → 0 | fixed | 1 | +2 −2 | $0.024 | 13s |
| py-urllib3 | urllib3 1.26.5 → 2.8.0 | 10 → 0 | fixed | 1 | +1 −1 | $0.018 | 13s |
| py-werkzeug | werkzeug 2.2.3 → 3.1.9 | 8 → 0 | fixed | 1 | +2 −2 | $0.017 | 13s |

All 47 known vulnerabilities were fixed and every project's tests still pass. Five upgrades broke the code and were repaired by the model in one round, changing one or two lines each: marked's removed callable export, PyJWT 2's required `algorithms` and `str` tokens, urllib3 2's `method_whitelist` → `allowed_methods`, Werkzeug 3's removed `url_quote`. Total model cost was about $0.10. Results are in `bench/RESULTS.md`. Model output varies between runs.

## Security model

Advisory text and upstream diffs are untrusted input to the LLM, so its output is constrained:

- Code edits are exact search/replace operations. They cannot touch `package.json`, lockfiles or anything outside the project, and backport edits stay inside the one package being patched.
- PoC scripts run under the Node.js permission model (`--permission`): read-only access to the project, no file writes, no child processes, no native addons, and a 10 s timeout.
- Nothing is kept unless your checks pass, and for backports the PoCs too.

## LLM backend

The LLM is called through a local CLI in headless mode (`-p --output-format json --json-schema …`) with tools, settings and session history disabled. That means it runs on your existing subscription and needs no API key. Configuration:

| Variable | Default | |
|---|---|---|
| `AUTOFIX_MODEL` | Sonnet 5.5 | model id |
| `AUTOFIX_EFFORT` | `medium` | reasoning effort |
| `AUTOFIX_LLM_BIN` | CLI on `PATH` | path to the CLI executable |
| `AUTOFIX_POETRY` | `poetry` | Poetry command, e.g. `uvx poetry` |

Typical cost in the examples above: $0.02–0.03 per upgrade repair, about $0.07 per backport (two PoCs plus the port).

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
- [ ] Fix pnpm and Yarn projects
- [x] Scan Python projects: uv, Poetry, Pipenv, requirements.txt; PEP 440 versions; import analysis that maps distributions to modules (`PyYAML` → `yaml`) via the virtualenv's `top_level.txt`
- [x] Fix uv and Poetry projects (upgrade + LLM repair)
- [ ] Fix Pipenv projects, Python backports

## License

MIT
