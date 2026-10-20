# Auto-FIX-CVE

[English](README.md) | **繁體中文**

大多數依賴掃描工具只會告訴你「升到 vX 就好」。Auto-FIX-CVE 會把流程做完：找出 CVE，定位**你的**程式碼裡哪幾行用到有漏洞的 API，再用兩種方式之一修好它。可以升級就升級，並修好升級後壞掉的程式碼；不能升級，就把上游的修補 backport 到你目前的版本。每個修補都會經過驗證，驗證沒過就 rollback。

在八個會弄壞程式碼的真實安全升級案例中（marked、PyJWT、urllib3、Werkzeug 等，涵蓋 npm、uv、Poetry、Pipenv），它修掉了全部 57 個漏洞，專案的測試也都還是通過。其中六次程式碼修正，模型都只用一輪就完成，總成本約 $0.12（[benchmark](#benchmark)）。

> 狀態：開發初期。支援矩陣：

| 生態系 | Lockfile | 掃描 + 可達性 | 修復（升級 + LLM 修正） | 遞移依賴修復 | Backport |
|---|---|---|---|---|---|
| JavaScript / TypeScript | npm、pnpm（v6–v9、多文件）、Yarn classic + Berry | AST import 分析 | npm、pnpm、Yarn | npm / pnpm 精準版本 override | npm |
| Python | uv、Poetry、Pipenv、固定版本的 `requirements.txt` | import 分析、`PyYAML` → `yaml` 對應 | uv、Poetry、Pipenv | uv constraints | — |
| Go | `go.mod` | import 分析 + advisory 的受影響函式清單 | `go.mod` + `go mod tidy` | 支援（明確 require） | — |
| Rust | `Cargo.lock` | `use` 分析 + RustSec 函式清單 | `Cargo.toml` + `cargo update` | `cargo update --precise` | — |

## 運作方式

```
1. 掃描      package-lock.json → OSV.dev → CVE、修復版本、fix commit
2. 影響分析  用 AST 找出所有 import / 呼叫有漏洞套件的位置
3. 計畫      upgrade / override（遞移依賴）/ backport / skip，你確認後才執行
4. 修復      A) 升級；驗證失敗就由 LLM 修正呼叫點
             B) backport：把上游 fix commit 移植到目前安裝的版本
5. 驗證      你的測試通過、重新掃描乾淨；backport 另外要求 PoC
             在修補前能重現漏洞、修補後通過
```

差異化：

- **建議的安全版本是真的安全，而且裝得起來**：每個升級目標都會再查一次 OSV，不會升級後又踩到其他 CVE；也會跳過已被 yank（PyPI、crates.io）或 deprecated（npm）的版本。例如 lodash 4.18.0 雖然修掉了 CVE，卻被官方標為「bad release」而 deprecated，所以會改為建議 4.18.1。
- **可達性提示**：每個結果會標成 `LIKELY REACHABLE`、`imported` 或 `not imported`；如果你呼叫的 API（例如 `_.template`）在 advisory 中被點名，會特別標出來；若 advisory 本身列出了受影響的函式（Go 和 RustSec 的 advisory 會列），則以該清單為準，而不是比對說明文字。遞移依賴會追到你實際呼叫的直接依賴，例如 `express` 底下的 `qs`，會顯示你使用 `express` 的那一行。
- **Backport 要有證據，不是假設**：PoC 必須在未修補的版本重現漏洞、在修補後通過，而且在重新安裝後依然通過，修補才會留下。
- **不為了修漏洞而引入新依賴**：backport 由一支零依賴的 postinstall 腳本重新套用，腳本會放進你的 repo。實測時，為此安裝的 `patch-package` 本身就帶進了一個有漏洞的遞移依賴。

## 使用方式

需要 Node.js ≥ 22.12 與 lockfile：`package-lock.json` / `npm-shrinkwrap.json`（v2/v3）、`pnpm-lock.yaml`（v6–v9）或 `yarn.lock`（v1 或 Berry）。Python 則是 `uv.lock`、`poetry.lock`、`Pipfile.lock` 或固定版本的 `requirements.txt`（會利用 pip-compile / `uv export` 的 `# via` 註解重建依賴圖）。Go 則是 `go.mod`，Rust 是 `Cargo.lock`。上述 lockfile 除了單純的 `requirements.txt` 以外，`fix` 都支援。Go 的作法是在 `go.mod` 提高 require 的版本（間接依賴也可以），執行 `go mod tidy`，再以 `go build ./...` 和 `go test ./...` 驗證。Rust 會改寫 `Cargo.toml` 的版本需求（`=` 精確鎖定的維持精確），遞移的 crate 則執行 `cargo update -p crate@old --precise new`；如果會破壞其他 crate 的版本需求，cargo 會直接拒絕。最後以 `cargo build` 和 `cargo test` 驗證。`fix` 另外需要本機的 LLM CLI（見 [LLM backend](#llm-backend)）。

不用安裝，直接從 GitHub 執行：

```bash
npx github:KJLavender/Auto-FIX-CVE scan path/to/project
```

或者 clone 下來使用（以下範例都用這種寫法）：

```bash
npm install                                 # 同時會 build 出 dist/
node dist/cli.js scan   path/to/project     # 回報 CVE 與程式碼中的使用位置
node dist/cli.js fix    path/to/project     # 計畫 → 確認 → 修復 → 驗證
node dist/cli.js verify path/to/project     # 重跑 backport 的 PoC（CI 用）
node dist/cli.js doctor                     # 檢查有哪些套件管理器 / 工具可用
```

`scan` 只需要能連到 OSV。`fix` 會呼叫專案本身的套件管理器和 LLM CLI；`doctor` 會列出已安裝的工具，以及每個工具對應的功能。

### 掃描

```bash
node dist/cli.js scan path/to/project --json      # 機器可讀格式
node dist/cli.js scan path/to/project --no-dev    # 略過只在開發時使用的依賴
node dist/cli.js scan path/to/repo -r             # 掃描 monorepo 裡的每個專案
```

同一個目錄同時有 JavaScript 和 Python 的 lockfile 時，兩個都會掃。`--recursive` 會往下走訪子目錄（略過 `node_modules`、virtualenv 和 build 輸出），每個專案各自列出一段結果，並把全部合併成一份 SARIF 報告。

結束碼：`0` 沒有漏洞，`1` 發現漏洞，`2` 錯誤。

範例（`test/fixtures/vuln-app`）：

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

#### LLM 可達性判讀

```bash
node dist/cli.js scan path/to/project --triage                 # 最多判讀 10 個套件
node dist/cli.js scan path/to/project --triage --max-cost 0.20  # 設定花費上限
node dist/cli.js scan path/to/project --triage --fail-on likely
```

對每個你的程式碼確實有用到的漏洞套件，模型會閱讀 advisory，以及每個呼叫點前後附行號的程式碼（遞移依賴則包含呼叫引入它的直接依賴的地方），回傳 `reachable`、`not reachable` 或 `unclear`、判斷理由，以及在什麼條件下會被利用：

```
requests@2.25.0  (direct)  LIKELY REACHABLE
  triage: unclear — ... The .netrc leak could apply, since requests.get reads .netrc by default and `url` may be attacker-influenced ...
idna@2.10  (transitive via requests)  imported
  triage: REACHABLE — fetch(url) calls requests.get(url), which encodes non-ASCII hostnames with idna.encode() ...
```

只有在程式碼本身就能排除所有 advisory 時，才允許判成 `not reachable`；取決於執行環境或輸入來源的情況一律是 `unclear`。搭配 `--fail-on likely` 時，`reachable` 會讓 build 失敗，`not reachable` 不會，`unclear` 則退回名稱比對的啟發式判斷。SARIF 中 `not reachable` 的警報會降為 note。判讀結果每次執行可能略有差異，請把它當成 review 的輔助。Python 範例的成本：五個套件約 $0.15。

### 接受的風險

把決定不修的漏洞記錄在 `.autofix-cve.json`。每條規則都必須附上理由，也可以設定到期日，到期後漏洞會重新出現，讓團隊再評估一次：

```json
{
  "$schema": "https://raw.githubusercontent.com/KJLavender/Auto-FIX-CVE/main/schema/autofix-cve.schema.json",
  "backports": [],
  "ignore": [
    { "id": "CVE-2021-44906", "package": "minimist", "reason": "only parses our own build script arguments", "until": "2027-01-01" }
  ]
}
```

`id` 可以填 GHSA、PYSEC、GO、RUSTSEC 或 CVE 編號。`$schema` 這一行（工具寫入檔案時會自動加上）讓編輯器提供自動完成，並標出缺少理由或日期格式錯誤的規則。被忽略的漏洞不會出現在結果、`--fail-on`、SARIF 和 `fix`（包含升級版本的搜尋）中，`scan` 則會列出它們和各自的理由。沒有理由或已經超過 `until` 日期的規則不會生效，`scan` 也會提示。

### 修復

```bash
node dist/cli.js fix path/to/project --dry-run          # 只顯示計畫
node dist/cli.js fix path/to/project --check "npm test" # 自訂驗證指令
node dist/cli.js fix path/to/project --only marked      # 只修指定套件
node dist/cli.js fix path/to/project --lockfile uv.lock # JS 與 Python 並存時指定要修哪一個
node dist/cli.js fix path/to/project --no-breaking      # 只做 semver 相容的升級
node dist/cli.js fix path/to/project --prefer-backport  # 用 backport 取代破壞性升級
node dist/cli.js fix path/to/project --no-backport      # 永不修改已安裝的套件
node dist/cli.js fix path/to/project --yes              # 不詢問（CI 用）
node dist/cli.js fix path/to/project --max-cost 0.50    # 模型花費超過 $0.50 就停止呼叫
node dist/cli.js fix path/to/project --pr               # commit 到新分支並開 GitHub PR
```

`fix` 會先列出計畫，問過你才動手：

```
Plan
  skip     axios 0.21.0 → 0.34.0  breaking upgrade with no build/test command to verify it (pass --check); no backport possible
  upgrade  lodash 4.17.20 → 4.18.0  5 vulns, likely
  upgrade  minimist 1.2.5 → 1.2.6  1 vuln, not-imported
  verify with: (none found)
  Nothing is downgraded. Failed fixes are rolled back.
Apply 2 change(s)? [y/N]
```

如何選擇動作：

| 情況 | 動作 |
|---|---|
| 修復版本與目前版本 semver 相容 | **upgrade**（直接依賴）或 **override**（遞移依賴；只針對有漏洞的確切版本，例如 `"qs@6.7.0": "6.16.0"`，同一套件的其他副本不受影響） |
| 修復版本是破壞性升級，且有驗證指令 | **upgrade**，驗證失敗時由 LLM 修正程式碼 |
| 破壞性升級，且指定了 `--prefer-backport` / `--no-breaking`，或沒有驗證指令 | **backport** |
| 遞移依賴需要破壞性升級 | **backport** |
| 還沒有修復版本，但上游已有 fix commit | **backport** |
| 升級在所有修正嘗試後仍失敗 | rollback 後改走 **backport** |
| 沒有可移植的 fix commit | **skip** |

安全規則：

- **絕不降版**：只會升到「比目前版本高、且 OSV 確認乾淨」的最小版本。
- **先問再做**：沒有終端機可以確認時，除非加 `--yes`，否則拒絕執行。
- **失敗就 rollback**：還原 `package.json`、lockfile、所有改過的檔案以及 `node_modules`；修到一半時模型無法使用，或 `--max-cost` 預算用完，也一樣會 rollback。
- **不會卡在互動提示**：子程序沒有 stdin，並設定 `CI=1`，原本會等你按 `y` 的指令會直接失敗；`npx` 也不會自己下載套件。
- **git 工作目錄不乾淨就拒絕執行**（可用 `--allow-dirty` 覆寫），方便事後用 `git diff` review。

#### 升級路線

1. 在動任何東西**之前**，先確認驗證指令（typecheck/build/test scripts 或 `--check`）是通過的。
2. 升級。如果 caret 範圍實際裝到更新的版本，也會再查一次 OSV。
3. 驗證失敗時，把錯誤輸出、使用位置、套件升級**前後**的 runtime exports、changelog 和相關檔案交給 LLM，LLM 回傳精確的 search/replace 修改。
4. 最多重試 `--max-attempts` 次（預設 3），仍失敗就 rollback。

uv 專案走的是同一套流程：改寫 `pyproject.toml`（固定版本的維持固定，範圍則改成以修復版本為下限）、遞移依賴寫進 `[tool.uv] constraint-dependencies`、執行 `uv lock` 與 `uv sync`，若專案有用 pytest 就以 `uv run pytest` 驗證。Poetry 專案也是同一套流程，另外會依專案原本的寫法（`^`、`~`、固定版本）改寫 Poetry 自己的 `[tool.poetry.*dependencies]` table；Pipenv 專案則以同樣方式改寫 `Pipfile`。Poetry 和 Pipenv 都沒有 override 機制，所以它們底下的遞移 Python 套件只會回報、不會修改。Python 範例（`test/fixtures/python-breaking-app`）：Werkzeug 2.2.3 → 3.1.9 修掉 16 個 CVE，模型把被移除的 `werkzeug.urls.url_quote` 換成 `urllib.parse.quote`。

範例（`test/fixtures/breaking-app`，marked 4 移除了可直接呼叫的 module export）：

```
FIXED  marked 2.1.3 → 4.3.0  upgrade
  model repair rounds: 1, cost: $0.0260
  model: marked 4.x no longer exports the module as a function; it exposes a named `marked` export. ...
  changed: package.json, package-lock.json, src/render.js
```

#### Backport 路線

1. 下載 advisory 連結的 fix commit，並把函式庫的修改和上游的測試分開。
2. **先證明漏洞存在**：LLM 根據 advisory 和上游測試寫出 PoC 檢查腳本，這支腳本必須在目前安裝的版本上判定為 *vulnerable*；做不到的 CVE 會保持開啟並回報出來。
3. 找出套件裡所有包含漏洞程式碼的副本（原始碼、CJS 與 ESM bundle、minified 版），由 LLM 把修補移植到每一份。
4. 反覆執行 PoC 直到全部通過，再跑你的驗證指令。
5. 把修改存成 `.autofix-cve/patches/<pkg>@<version>.json`，並在 `postinstall` 加上 `node .autofix-cve/apply-patches.cjs`。
6. 刪除套件、重新安裝，再跑一次 PoC，證明修補在 `npm install` / `npm ci` 之後依然有效。

範例（在 `test/fixtures/breaking-app` 執行 `fix --prefer-backport`）：

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

Backport 會在你的 repo 加入這些檔案：

```
.autofix-cve.json                         記錄哪些 CVE、針對哪個確切版本做了 backport
.autofix-cve/apply-patches.cjs            零依賴的 postinstall 腳本
.autofix-cve/patches/marked@2.1.3.json    search/replace 修改內容
.autofix-cve/poc/GHSA-….cjs               證明修補有效的 PoC
```

`scan` **只在版本完全相同、且修補確實套用中**時，才會把這些 CVE 視為已修復。套件版本一變，或安裝時略過了 scripts，這些 CVE 就會重新被回報。

#### Pull request

加上 `--pr` 時，修補會 commit 到新的 `autofix-cve/<timestamp>` 分支、push，再用 `gh` 開成 pull request。開始修復之前會先檢查前置條件：必須有 checkout 的分支、指向 GitHub 的 `origin` remote，以及已登入的 `gh`。PR 內容會列出每個修好的 CVE 及其證據（通過的驗證指令、PoC 判定、OSV 確認）、模型對每處程式碼修改的說明、沒修好的項目與原因，以及重新掃描的結果。如果什麼都沒修好，就刪除這個分支。

### 驗證（CI）

```bash
node dist/cli.js verify path/to/project
```

重跑所有存下的 PoC，只要有任何漏洞重新出現（例如用 `--ignore-scripts` 安裝後），就以 `1` 結束。

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
  security-events: write   # 上傳 SARIF 需要
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-node@v7
        with:
          node-version: 22
      - run: npm ci            # 透過 postinstall 套用 backport，verify 需要
      - uses: KJLavender/Auto-FIX-CVE@main
        with:
          fail-on: likely      # any | likely | high | none
```

這個 action 會掃描、把 Markdown 表格寫進 job summary、把 SARIF 報告上傳到 code scanning；專案有 backport 時也會執行 `verify`。Alert 會出現在 lockfile 的套件項目上，**也會出現在呼叫 advisory 點名的 API 的那一行程式碼**。可用的輸入：`path`、`recursive`、`baseline`、`fail-on`、`include-dev`、`sarif-file`、`upload-sarif`、`verify`。

在本機也能用相同的選項：

```bash
node dist/cli.js scan . --sarif results.sarif --markdown summary.md --fail-on likely
```

要在舊專案導入嗎？先把目前已有的漏洞記錄下來，之後只有新出現的漏洞會讓 build 失敗；已知的漏洞仍會顯示在報告中：

```bash
node dist/cli.js scan . --baseline .autofix-baseline.json --update-baseline   # 執行一次，並 commit 這個檔案
node dist/cli.js scan . --baseline .autofix-baseline.json                     # 在 CI 中
```

## Benchmark

八個真實的安全升級案例，都是升級後會（或可能會）讓程式碼壞掉的情況，每個案例都是附有測試的小專案（`bench/cases`）。`npm run bench` 會把每個案例複製到暫存目錄、執行 `fix --yes`，並量測結果：

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

57 個已知漏洞全部修掉，每個專案的測試也都還是通過。其中六個升級弄壞了程式碼，模型各用一輪修好，每個只改一到兩行：marked 移除了可直接呼叫的 export、PyJWT 2 要求指定 `algorithms` 且 token 改為 `str`、urllib3 2 把 `method_whitelist` 改名為 `allowed_methods`（uv 與 Pipenv 各一次）、Werkzeug 3 移除了 `url_quote`。模型總成本約 $0.12。結果記錄在 `bench/RESULTS.md`。模型輸出每次執行可能略有不同。

## 安全模型

Advisory 內文和上游 diff 對 LLM 來說都是不可信的輸入，所以會限制它的輸出：

- 程式碼修改只能是精確的 search/replace，不能動 `package.json`、lockfile 或專案以外的任何東西；backport 的修改只能落在被修補的那一個套件內。
- PoC 腳本在 Node.js permission model（`--permission`）下執行：專案唯讀、不能寫檔、不能開子程序、不能載入原生模組，並有 10 秒逾時。
- 必須通過你的驗證指令（backport 還要通過 PoC），修改才會留下。

## LLM backend

LLM 透過本機 CLI 以 headless 模式呼叫（`-p --output-format json --json-schema …`），並關閉 tools、設定檔與 session 紀錄，走你現有的訂閱，不需要 API key。設定方式：

| 變數 | 預設值 | |
|---|---|---|
| `AUTOFIX_MODEL` | Sonnet 5.5 | 模型 id |
| `AUTOFIX_EFFORT` | `medium` | 推理強度 |
| `AUTOFIX_LLM_BIN` | `PATH` 上的 CLI | CLI 執行檔路徑 |
| `AUTOFIX_POETRY` | `poetry` | Poetry 指令，例如 `uvx poetry` |
| `AUTOFIX_PIPENV` | `pipenv` | Pipenv 指令，例如 `uvx pipenv` |
| `AUTOFIX_PNPM` / `AUTOFIX_YARN` | `pnpm` / `yarn` | pnpm / Yarn 指令，例如 `npx pnpm@9` |

上面範例的實際成本：每次升級修正約 $0.02–0.03，每次 backport 約 $0.07（兩個 PoC 加上移植）。

## 常見問題

**它會自己幫我升版或降版嗎？** 絕不降版：目標版本必須高於目前安裝的版本，否則直接跳過。它也不會沒問過你就升版：`fix` 會先列出計畫（每個套件要 upgrade、override、backport 還是 skip，以及原因），等你按 `y` 才執行。沒有終端機時，除非加上 `--yes`，否則拒絕執行。`scan` 則完全不會修改任何東西。

**升級把我的程式碼弄壞了怎麼辦？** 動手之前會先跑你的驗證指令，原本就失敗的情況不會被算到升級頭上。升級後驗證失敗時，會交給 LLM 修正呼叫端的程式碼（最多 `--max-attempts` 次，預設 3 次）；還是失敗就全部 rollback，包括 manifest、lockfile、改過的檔案和已安裝的套件。沒有驗證指令時，不會嘗試破壞性升級。`--no-breaking` 只做相容的升級，`--prefer-backport` 則改成直接修補目前的版本（npm）。

**會不會卡在「Ok to proceed? (y)」這類提示？** 不會。子程序沒有 stdin，並設定 `CI=1`，原本會等待輸入的指令會直接失敗；`npx` 也不會自己下載套件。唯一的提示只有開頭的計畫確認。

**需要 API key 嗎？** 不需要。LLM 透過本機 CLI 執行，走你現有的訂閱（見 [LLM backend](#llm-backend)）。`scan` 完全不需要 LLM。

## 開發

```bash
npm test            # 單元測試（不需要網路）
npm run typecheck
npm run dev -- scan test/fixtures/vuln-app
```

`test/fixtures/` 底下的範例專案是故意含有漏洞的。`fix` 會直接修改專案，執行前請先複製到暫存目錄。

## 路線圖

- [x] 解析 npm lockfile，並追蹤依賴來源
- [x] 查詢 OSV、搜尋安全版本、擷取 fix commit
- [x] 以 AST 分析使用位置（ESM、CommonJS、dynamic import、re-export）
- [x] 升級路線：LLM 修正與 rollback
- [x] Backport 路線：PoC 證明、零依賴的修補保存、`verify`
- [x] 產生附上驗證證據的 PR
- [x] GitHub Action 與 SARIF 上傳（code scanning 直接標註呼叫點）
- [x] 掃描 pnpm 與 Yarn lockfile
- [x] 修復 pnpm 專案（精準版本的 `pnpm.overrides`）與 Yarn 專案（僅限宣告的套件；Yarn resolutions 無法只針對單一版本）
- [x] 掃描 Python 專案：uv、Poetry、Pipenv、requirements.txt；支援 PEP 440 版本規則；import 分析會把套件名對應到模組名（`PyYAML` → `yaml`），優先讀 virtualenv 裡的 `top_level.txt`
- [x] 修復 uv、Poetry 與 Pipenv 專案（升級加 LLM 修正）
- [x] 掃描 Go module（`go.mod`、import 分析、以 advisory 列出的受影響函式判斷可達性）
- [x] 修復 Go module（`go.mod` + `go mod tidy`，在 CI 中用 Go 工具鏈實際驗證）
- [x] 掃描與修復 Rust crate（`Cargo.lock`、`use` 樹、RustSec 的函式清單、`cargo update --precise`，在 CI 中用 cargo 實際驗證）
- [ ] Python backport：刻意暫不實作，原因有兩個。Python 的套件管理器沒有 post-install hook，修改 site-packages 的修補會在下一次 `uv sync` / `pip install` 時悄悄消失；而且 Python 沒有像 Node 那樣的內建 permission sandbox，執行模型根據不可信的 advisory 寫出的 PoC 時，無法做到同等程度的隔離。

## 授權

MIT
