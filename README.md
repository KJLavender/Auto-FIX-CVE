# Auto-FIX-CVE

**English** | [繁體中文](README.zh-TW.md)

Most dependency scanners stop at "upgrade to vX". Auto-FIX-CVE is being built to close the loop: find the CVE, locate the exact lines in **your** code that use the vulnerable API, then fix it, either by upgrading and rewriting the code that breaks or by backporting the upstream patch when you can't upgrade, and verify the result.

> Status: early development. For npm projects, scanning, impact analysis and the upgrade path (strategy A) work. Backporting (strategy B) and PR generation are on the roadmap.

## How it works

```
1. Scan        package-lock.json → OSV.dev → CVEs, fixed versions, fix commits
2. Impact      AST analysis finds every import / call of the vulnerable package
3. Strategy    A) upgrade + LLM rewrites broken call sites until tests pass
               B) backport the upstream fix commit as a patch-package patch
4. Verify      tests pass, rescan is clean, PoC (if any) no longer works
5. Report      open a PR with the CVE, chosen strategy, diff and evidence
```

What already sets the scanner apart:

- **Safe version that is actually safe.** The suggested upgrade target is re-checked against OSV, so you never upgrade into a different CVE.
- **Reachability hints.** Each finding is labelled `LIKELY REACHABLE`, `imported` or `not imported`. A usage is flagged when the API it calls (e.g. `_.template`) is named in the advisory.
- **Breaking-change awareness.** Semver-breaking upgrades are flagged, including `0.x` minor bumps.
- **Transitive provenance.** Transitive packages show which direct dependency pulls them in.

## Usage

Requires Node.js ≥ 20 and a `package-lock.json` (lockfile v2/v3).

```bash
npm install
npm run build
node dist/cli.js scan path/to/project
node dist/cli.js scan path/to/project --json      # machine-readable
node dist/cli.js scan path/to/project --no-dev    # skip dev-only deps
```

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

### Fix

```bash
node dist/cli.js fix path/to/project                    # verify with typecheck/build/test scripts
node dist/cli.js fix path/to/project --check "npm test" # custom verification command(s)
node dist/cli.js fix path/to/project --only marked      # one package
node dist/cli.js fix path/to/project --dry-run          # show the plan only
node dist/cli.js fix path/to/project --no-breaking      # semver-compatible upgrades only
node dist/cli.js fix path/to/project --yes              # no prompt (CI)
```

`fix` first prints a plan and asks before changing anything:

```
Plan
  skip     axios 0.21.0 → 0.34.0  breaking upgrade but no build/test command to verify it; pass --check
  upgrade  lodash 4.17.20 → 4.18.0  5 vulns, likely
  upgrade  minimist 1.2.5 → 1.2.6  1 vuln, not-imported
  verify with: (none found)
  Nothing is downgraded. Failed fixes are rolled back.
Apply 2 change(s)? [y/N]
```

Safety rules:

- **Never downgrades.** It only moves to the smallest version above the current one that OSV reports as clean.
- **Asks first.** Without a terminal it refuses to run unless you pass `--yes`.
- **Breaking upgrades need proof.** They are only attempted when there is a build/test command to verify them, and `--no-breaking` turns them off entirely. A transitive dependency that needs a breaking upgrade is skipped (left for the backport path).
- **Won't hang on prompts.** Child commands run without stdin and with `CI=1`, so anything that would wait for a `y` fails instead, and `npx` never downloads packages on its own.
- **Refuses a dirty git tree** (override with `--allow-dirty`) so the result is easy to review with `git diff`.

For each package in the plan, `fix`:

1. Confirms your checks pass **before** touching anything.
2. Upgrades to the verified safe version (direct deps via `package.json`, non-breaking transitive deps via `overrides`). If the caret range resolves to a newer version, that version is checked against OSV too.
3. Runs the checks. If they fail, it sends the model the failing output, the usage sites, the package's runtime exports **before vs. after** the upgrade, its changelog, and the relevant files. The model answers with exact search/replace edits.
4. Repeats up to `--max-attempts` (default 3). If the checks still fail, it **rolls back** `package.json`, the lockfile, every edited file and `node_modules`.
5. Rescans and leaves the changes in your working tree for review.

The model is called through the local [Claude Code](https://docs.claude.com/en/docs/claude-code) CLI in headless mode (`claude -p --json-schema`), so it uses your Claude subscription and needs no API key. Defaults to `claude-sonnet-5-5`. Override with `AUTOFIX_MODEL`, `AUTOFIX_EFFORT` (default `medium`) and `AUTOFIX_CLAUDE_BIN`.

Example (from `test/fixtures/breaking-app`, where marked 4 removed the callable module export):

```
marked@2.1.3
  upgrade marked 2.1.3 → 4.0.10
  `npm test` fails; asking the model for a fix (attempt 1/3)

FIXED  marked 2.1.3 → 4.3.0  upgrade
  model repair rounds: 1, cost: $0.0260
  model: marked 4.x no longer exports the module as a function; it exposes a named `marked` export. ...
  changed: package.json, package-lock.json, src/render.js

Rescan is clean.
```

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
- [x] Upgrade path: apply upgrade, run build/tests, LLM-guided fixes with rollback (Claude Sonnet 5.5)
- [ ] Backport path: port fix commit to the installed version via patch-package
- [ ] Verification and PR generation
- [ ] GitHub Action
- [ ] Python (pip / poetry / uv) support

## License

MIT
