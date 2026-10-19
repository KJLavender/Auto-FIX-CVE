# Auto-FIX-CVE

[English](README.md) | **繁體中文**

大多數依賴掃描工具只會告訴你「升到 vX 就好」。Auto-FIX-CVE 會把流程做完：找出 CVE，定位**你的**程式碼裡哪幾行用到有漏洞的 API，再用兩種方式之一修好它。可以升級就升級，並修好升級後壞掉的程式碼；不能升級，就把上游的修補 backport 到你目前的版本。每個修補都會經過驗證，驗證沒過就 rollback。

> 狀態：開發初期。`scan` 支援 npm、pnpm、Yarn（classic 與 Berry）的 lockfile；`fix`（升級、backport、PR）目前支援 npm 專案。Python 支援規劃中。

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

- **建議的安全版本是真的安全**：每個升級目標都會再查一次 OSV，不會升級後又踩到其他 CVE。
- **可達性提示**：每個結果會標成 `LIKELY REACHABLE`、`imported` 或 `not imported`；如果你呼叫的 API（例如 `_.template`）在 advisory 中被點名，會特別標出來。遞移依賴會追到你實際呼叫的直接依賴，例如 `express` 底下的 `qs`，會顯示你使用 `express` 的那一行。
- **Backport 要有證據，不是假設**：PoC 必須在未修補的版本重現漏洞、在修補後通過，而且在重新安裝後依然通過，修補才會留下。
- **不為了修漏洞而引入新依賴**：backport 由一支零依賴的 postinstall 腳本重新套用，腳本會放進你的 repo。實測時，為此安裝的 `patch-package` 本身就帶進了一個有漏洞的遞移依賴。

## 使用方式

需要 Node.js ≥ 22.12 與 lockfile：`package-lock.json` / `npm-shrinkwrap.json`（v2/v3）、`pnpm-lock.yaml`（v6–v9）或 `yarn.lock`（v1 或 Berry）。`fix` 需要 `package-lock.json`。`fix` 另外需要本機的 LLM CLI（見 [LLM backend](#llm-backend)）。

```bash
npm install
npm run build
node dist/cli.js scan   path/to/project     # 回報 CVE 與程式碼中的使用位置
node dist/cli.js fix    path/to/project     # 計畫 → 確認 → 修復 → 驗證
node dist/cli.js verify path/to/project     # 重跑 backport 的 PoC（CI 用）
```

### 掃描

```bash
node dist/cli.js scan path/to/project --json      # 機器可讀格式
node dist/cli.js scan path/to/project --no-dev    # 略過只在開發時使用的依賴
```

結束碼：`0` 沒有漏洞，`1` 發現漏洞，`2` 錯誤。

範例（`test/fixtures/vuln-app`）：

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

### 修復

```bash
node dist/cli.js fix path/to/project --dry-run          # 只顯示計畫
node dist/cli.js fix path/to/project --check "npm test" # 自訂驗證指令
node dist/cli.js fix path/to/project --only marked      # 只修指定套件
node dist/cli.js fix path/to/project --no-breaking      # 只做 semver 相容的升級
node dist/cli.js fix path/to/project --prefer-backport  # 用 backport 取代破壞性升級
node dist/cli.js fix path/to/project --no-backport      # 永不修改已安裝的套件
node dist/cli.js fix path/to/project --yes              # 不詢問（CI 用）
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
- **失敗就 rollback**：還原 `package.json`、lockfile、所有改過的檔案以及 `node_modules`。
- **不會卡在互動提示**：子程序沒有 stdin，並設定 `CI=1`，原本會等你按 `y` 的指令會直接失敗；`npx` 也不會自己下載套件。
- **git 工作目錄不乾淨就拒絕執行**（可用 `--allow-dirty` 覆寫），方便事後用 `git diff` review。

#### 升級路線

1. 在動任何東西**之前**，先確認驗證指令（typecheck/build/test scripts 或 `--check`）是通過的。
2. 升級。如果 caret 範圍實際裝到更新的版本，也會再查一次 OSV。
3. 驗證失敗時，把錯誤輸出、使用位置、套件升級**前後**的 runtime exports、changelog 和相關檔案交給 LLM，LLM 回傳精確的 search/replace 修改。
4. 最多重試 `--max-attempts` 次（預設 3），仍失敗就 rollback。

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

這個 action 會掃描、把 SARIF 報告上傳到 code scanning；專案有 backport 時也會執行 `verify`。Alert 會出現在 lockfile 的套件項目上，**也會出現在呼叫 advisory 點名的 API 的那一行程式碼**。可用的輸入：`path`、`fail-on`、`include-dev`、`sarif-file`、`upload-sarif`、`verify`。

在本機也能用相同的選項：

```bash
node dist/cli.js scan . --sarif results.sarif --fail-on likely
```

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

上面範例的實際成本：每次升級修正約 $0.02–0.03，每次 backport 約 $0.07（兩個 PoC 加上移植）。

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
- [ ] 修復 pnpm 與 Yarn 專案
- [ ] 支援 Python（pip / poetry / uv）

## 授權

MIT
