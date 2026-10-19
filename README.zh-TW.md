# Auto-FIX-CVE

[English](README.md) | **繁體中文**

大多數依賴掃描工具只會告訴你「升到 vX 就好」。Auto-FIX-CVE 的目標是把整個流程做完：找出 CVE，定位**你的**程式碼裡哪幾行用到有漏洞的 API，然後修好它。能升級就升級，並改寫升級後壞掉的程式碼；不能升級就把上游的修補 backport 回目前的版本。最後還會驗證修補結果。

> 狀態：開發初期。npm 專案的掃描、影響分析與升級路線（策略 A）已可使用；Backport（策略 B）與產生 PR 規劃中。

## 運作方式

```
1. 掃描      package-lock.json → OSV.dev → CVE、修復版本、fix commit
2. 影響分析  用 AST 找出所有 import / 呼叫有漏洞套件的位置
3. 選策略    A) 升級，由 LLM 改寫壞掉的呼叫點，直到測試通過
             B) 把上游 fix commit backport 成 patch-package 修補檔
4. 驗證      測試通過、重新掃描乾淨、PoC（若有）不再成功
5. 報告      開 PR，附上 CVE、選用的策略、diff 與驗證證據
```

目前掃描器的差異化：

- **建議的安全版本真的安全**：升級目標會再查一次 OSV，避免升級後又踩到其他 CVE。
- **可達性提示**：每個結果會標成 `LIKELY REACHABLE`、`imported` 或 `not imported`。如果你呼叫的 API（例如 `_.template`）在 advisory 中被點名，就會特別標出來。
- **Breaking change 判斷**：依 semver 標出破壞性升級，包含 `0.x` 的 minor 升級。
- **遞移依賴來源**：遞移套件會顯示是被哪個直接依賴引入的。

## 使用方式

需要 Node.js ≥ 20，以及 `package-lock.json`（lockfile v2/v3）。

```bash
npm install
npm run build
node dist/cli.js scan path/to/project
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
node dist/cli.js fix path/to/project                    # 用 typecheck/build/test scripts 驗證
node dist/cli.js fix path/to/project --check "npm test" # 自訂驗證指令
node dist/cli.js fix path/to/project --only marked      # 只修指定套件
node dist/cli.js fix path/to/project --dry-run          # 只顯示計畫
node dist/cli.js fix path/to/project --no-breaking      # 只做 semver 相容的升級
node dist/cli.js fix path/to/project --yes              # 不詢問（CI 用）
```

`fix` 會先列出計畫，問過你才動手：

```
Plan
  skip     axios 0.21.0 → 0.34.0  breaking upgrade but no build/test command to verify it; pass --check
  upgrade  lodash 4.17.20 → 4.18.0  5 vulns, likely
  upgrade  minimist 1.2.5 → 1.2.6  1 vuln, not-imported
  verify with: (none found)
  Nothing is downgraded. Failed fixes are rolled back.
Apply 2 change(s)? [y/N]
```

安全規則：

- **絕不降版**：只會升到「比目前版本高、且 OSV 確認乾淨」的最小版本。
- **先問再做**：沒有終端機可以確認時，除非加 `--yes`，否則拒絕執行。
- **破壞性升級要有證據**：必須有 build/test 指令可以驗證才會嘗試；`--no-breaking` 可以完全關閉。遞移依賴需要破壞性升級時會跳過（留給 backport 路線處理）。
- **不會卡在互動提示**：子程序沒有 stdin，並設定 `CI=1`，原本會等你按 `y` 的指令會直接失敗；`npx` 也不會自己下載套件。
- **git 工作目錄不乾淨就拒絕執行**（可用 `--allow-dirty` 覆寫），方便事後用 `git diff` review。

對計畫中的每個套件，`fix` 會依序：

1. 在動任何東西**之前**，先確認驗證指令是通過的。
2. 升級到已驗證的安全版本：直接依賴改 `package.json`，非破壞性的遞移依賴用 `overrides`。如果 caret 範圍實際裝到更新的版本，也會再查一次 OSV。
3. 執行驗證。失敗的話，把錯誤輸出、使用位置、套件升級**前後**的 runtime exports、changelog 和相關檔案交給模型，模型回傳精確的 search/replace 修改。
4. 最多重試 `--max-attempts` 次（預設 3）。仍然失敗就**完整 rollback**：`package.json`、lockfile、所有改過的檔案以及 `node_modules`。
5. 重新掃描，並把修改留在工作目錄讓你 review。

模型透過本機的 [Claude Code](https://docs.claude.com/en/docs/claude-code) CLI 以 headless 模式呼叫（`claude -p --json-schema`），走你的 Claude 訂閱，不需要 API key。預設模型為 `claude-sonnet-5-5`，可用 `AUTOFIX_MODEL`、`AUTOFIX_EFFORT`（預設 `medium`）、`AUTOFIX_CLAUDE_BIN` 覆寫。

範例（`test/fixtures/breaking-app`，marked 4 移除了可直接呼叫的 module export）：

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
- [x] 升級路線：套用升級、跑 build/測試、由 LLM 修正，失敗時 rollback（Claude Sonnet 5.5）
- [ ] Backport 路線：用 patch-package 把 fix commit 移植到目前版本
- [ ] 驗證與產生 PR
- [ ] GitHub Action
- [ ] 支援 Python（pip / poetry / uv）

## 授權

MIT
