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
| .NET（C#） | `packages.lock.json`、`obj/project.assets.json` | `using` / 完整限定名稱分析 | `.csproj` 或 `Directory.Packages.props` + `dotnet restore` | 直接加 `PackageReference` 釘版 | — |

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

需要 Node.js ≥ 22.12 與 lockfile：`package-lock.json` / `npm-shrinkwrap.json`（v2/v3）、`pnpm-lock.yaml`（v6–v9）或 `yarn.lock`（v1 或 Berry）。Python 則是 `uv.lock`、`poetry.lock`、`Pipfile.lock` 或固定版本的 `requirements.txt`（會利用 pip-compile / `uv export` 的 `# via` 註解重建依賴圖）。Go 則是 `go.mod`，Rust 是 `Cargo.lock`。.NET 是 `packages.lock.json`，或每次 `dotnet restore` 都會產生的 `obj/project.assets.json`，所以沒有 NuGet lockfile 的專案也能用（`PrivateAssets="all"` 的套件，例如 analyzer，視為只在 build 時使用）。上述 lockfile 除了單純的 `requirements.txt` 以外，`fix` 都支援。Go 的作法是在 `go.mod` 提高 require 的版本（間接依賴也可以），執行 `go mod tidy`，再以 `go build ./...` 和 `go test ./...` 驗證。Rust 會改寫 `Cargo.toml` 的版本需求（`=` 精確鎖定的維持精確），遞移的 crate 則執行 `cargo update -p crate@old --precise new`；如果會破壞其他 crate 的版本需求，cargo 會直接拒絕。最後以 `cargo build` 和 `cargo test` 驗證。.NET 會提高專案檔中 `PackageReference` 的版本（使用 Central Package Management 時則改 `Directory.Packages.props` 的 `PackageVersion`），間接套件則以修好的版本直接加一筆參考來釘版，接著執行 `dotnet restore`（有 lockfile 時加上 `--force-evaluate`），再以 `dotnet build` 驗證，測試專案另外跑 `dotnet test`。C# 的可達性以命名空間判斷：`using` 指示詞、別名與完整限定名稱。`fix` 另外需要本機的 LLM CLI（見 [LLM backend](#llm-backend)）。

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
node dist/cli.js scan path/to/project --min-severity high   # 隱藏 low 與 moderate
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

#### 惡意套件

有些公告講的不是 bug，而是套件本身（或被劫持的某一版）就是惡意程式，例如 `event-stream` 3.3.6、`flatmap-stream`，以及各種 typosquat。這些資料來自 OpenSSF malicious-packages（`MAL-…` 編號）與 GitHub 的 malware 公告（CWE-506），兩者都收錄在 OSV 中，處理方式和一般漏洞不同：

- 以 `MALICIOUS PACKAGE` 標示並排在最前面，一律視為 critical，並提醒你移除套件、把那台機器上的密鑰都當成已外洩，因為它在安裝時就已經執行了；
- 不論可達性，任何 `--fail-on` 等級（`none` 除外）都會失敗，ignore 規則也不能接受它；
- 有乾淨版本時 `fix` 會換掉這個版本，沒有就拒絕並提示「請移除」；絕不對惡意程式做 backport 或 `mitigate`，`--vex` 也絕不會聲明它不影響你。

#### 依風險擋 build

```bash
node dist/cli.js scan path/to/project --fail-on risk
```

只看嚴重度會擋太多：一個你根本沒呼叫到的 HIGH 漏洞可以卡住 build 好幾週，而正在被攻擊的 MODERATE 漏洞卻能過關。`--fail-on risk` 只在真正要緊的情況下失敗：

- 任何列在 CISA [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)（已在外面被實際攻擊）清單裡的漏洞，不論評級；或
- 你的程式碼會走到的 high 或 critical 漏洞（`likely`，或 triage 判成 `reachable`；判成 `not reachable` 則不算）。

已知被利用的漏洞會排在最前面，並在報告、Markdown 和 SARIF 中標上 `KNOWN EXPLOITED`（SARIF 一律為 error）。其他漏洞照樣會列出，可以排進修補時程，而不用卡在上線流程上。清單每次執行下載一次；要用本機的副本請見[鏡像與離線使用](#鏡像與離線使用)。

每個 CVE 也會帶上 [EPSS](https://www.first.org/epss/) 分數，也就是 FIRST 估計它在未來 30 天內被利用的機率。1% 以上的分數會顯示在 advisory 旁（`EPSS 36%`），也會寫進 Markdown 與 SARIF；可達性與嚴重度相同的結果會再依它排序。`--epss-threshold 0.1` 讓 `--fail-on risk` 也對 10% 以上的漏洞失敗，可以在剛公布的 bug 進入 KEV 清單之前就抓到：Node2Shell 發布五天後的分數是 36%（第 98 百分位）。

#### 已部署的映像（SBOM）

```bash
trivy image --format cyclonedx -o api.cdx.json registry.example.com/shop/api:<部署中的 tag>
node dist/cli.js scan . --sbom api.cdx.json --baseline api.baseline.json --fail-on risk
```

pipeline 只在有人 push 時才檢查程式碼。新的 CVE 公布時，已經在跑的映像要等到下一次改動才會被重新檢查。`--sbom` 改為掃描 CycloneDX 或 SPDX JSON 格式的 SBOM，而不是 lockfile：可以是 `trivy image` 的輸出，或 Harbor 為映像產生的 SBOM。排程對「部署中映像」的 SBOM 執行並搭配 baseline，只有出現**新的**問題時 job 才會失敗，例如某個套件剛被列入 KEV 清單。SBOM 中的 npm、PyPI、Go、crates.io 和 NuGet 套件都會檢查，也會算出每個間接套件是由哪個直接依賴帶進來的。**OS 套件**也會檢查，支援 Debian、Ubuntu、Alpine、AlmaLinux 與 Rocky Linux 映像，比對 OSV 針對該發行版本的公告（`Debian:12`、`Ubuntu:22.04:LTS`、`Alpine:v3.20`、`AlmaLinux:9`、`Rocky Linux:9`），版本照 dpkg、apk、rpm 各自的規則比較。Debian、Ubuntu 和 Alpine 的公告以 source package（`brotli`）為單位，而映像裡裝的是由它建出來的 binary（`libbrotli1`），所以會把 binary 歸到所屬的 source package 底下（取自 Trivy 的 `SrcName`/`SrcVersion` 或 SPDX 的 `sourceInfo`）。其他系統（RHEL、Amazon Linux）和套件類型只計數、不檢查，請交給 Trivy。

若是從離線鏡像安裝 OS 套件，`--os-list <file>` 會為每個「升級可以修好」的已安裝 binary 寫一行版本釘選，格式依套件管理工具而定（apt 是 `libbrotli1=1.0.9-2+deb12u1`、apk 是 `libssl3=3.1.8-r1`、dnf 是 `openssl-libs-1:3.5.8-2.el9_8`），可以直接拿到能上網的機器下載，再上傳到鏡像。因為沒有原始碼，可達性無法判斷，所以請用 `--fail-on any`、`high` 或 `risk`（此時等於「已知被利用」）。`[dir]` 裡 `.autofix-cve.json` 的 ignore 規則照樣有效。Node.js 和 .NET runtime 常常不在 SBOM 裡，請搭配 `runtime` 一起用。

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

#### 給其他掃描器用的 VEX

```bash
node dist/cli.js scan . --triage --vex app.vex.json
trivy image --vex app.vex.json registry.example.com/shop/api:abc123
```

registry 或掃描器的 allowlist 只說「別再報這個」，不說為什麼，而且條目常常比當初的理由活得更久。`--vex <file>` 改為輸出 [OpenVEX](https://openvex.dev) 文件，只為這個工具真的有依據的漏洞寫 statement：

- 模型 triage 判成**不可達**的套件：`not_affected` / `vulnerable_code_not_in_execute_path`，並以模型的理由作為 impact statement；
- 帶有 OpenVEX `justification` 的 ignore 規則（例如在 `reason` 旁寫 `"justification": "vulnerable_code_cannot_be_controlled_by_adversary"`）：`not_affected`；規則的 `until` 日期也會結束這筆 statement，因為過期的規則不會生效；
- 驗證過的 backport：`fixed`。

沒有 `justification` 的 ignore 規則只在本工具內接受風險，不會對其他工具做任何聲明。每筆 statement 以 purl 指出套件（Debian 套件用已安裝的 binary）。`--vex-product <purl>` 會把它們列為某個產品（例如容器映像 `pkg:oci/…`）的 subcomponent，這是 Trivy 對映像的要求。把這個檔案和程式碼一起放進 Git，每一筆例外就會像其他修改一樣經過 review。

### Vet（加入套件之前）

```bash
node dist/cli.js vet lodash@4.17.20 left-pad pypi:requests==2.31.0 go:github.com/gin-gonic/gin@v1.9.0 cargo:serde nuget:Newtonsoft.Json@12.0.1
node dist/cli.js vet axios --deny-license GPL-3.0 AGPL-3.0 --strict --json
```

其他指令看的是已經安裝的東西；`vet` 是門口的檢查。對每個套件（預設 npm；其他用 `pypi:`、`go:`、`cargo:`、`nuget:` 前綴；沒指定版本就看最新版）回報：

- **惡意程式**，包含已經從 registry 下架的版本（`event-stream@3.3.6` 在 npm 上「找不到」，但仍會標成惡意，因為鏡像和舊的 lockfile 可能還留著）；
- **已知漏洞**，附 KEV、EPSS，以及修好的版本；
- **已 deprecated 或 yanked** 的版本；
- **發布時間**：未滿 `--min-age` 天（預設 7 天）會警告，因為被劫持的版本通常幾天內就會被發現；
- **授權條款**，以 SPDX 表示式比對 `--allow-license` / `--deny-license`（`Apache 2.0` 這類自由文字會先正規化）；`MIT OR GPL-3.0` 可以透過 MIT 這個選項通過 GPL 禁令，`MIT AND GPL-3.0` 則不行。

每個套件得到 PASS、WARN 或 FAIL，只要有一個 FAIL，exit code 就是 1（加上 `--strict` 時警告也算失敗），所以可以當成新增依賴時的 pre-commit 或 pipeline 步驟。資料來自各 registry 的公開 API（`AUTOFIX_NPM_REGISTRY`、`AUTOFIX_PYPI_URL`、`AUTOFIX_CRATES_API`、`AUTOFIX_GO_PROXY`、`AUTOFIX_NUGET_API` 可以改指向鏡像）。

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

加上 `--pr` 時，修補會 commit 到新的 `autofix-cve/<timestamp>` 分支、push，再開成 pull request：`origin` 在 GitHub 時用 `gh`，其他主機一律當成 GitLab（含自架），**透過 REST API 開 merge request**。開始修復之前會先檢查前置條件：必須有 checkout 的分支、`origin` remote，以及已登入的 `gh` 或放在 `AUTOFIX_GITLAB_TOKEN` 中、具 `api` 權限的 GitLab token。通用的 `GITLAB_TOKEN` 也可以用，但只會送往它所屬的主機（跟 `glab` 一樣看 `GITLAB_HOST`，未設定則為 gitlab.com），避免某個站台的 token 被送到另一個站台。API 位址取自 remote；在 GitLab CI 裡用 `CI_API_V4_URL`，也可用 `AUTOFIX_GITLAB_API` 指定。PR 內容會列出每個修好的 CVE 及其證據（通過的驗證指令、PoC 判定、OSV 確認）、模型對每處程式碼修改的說明、沒修好的項目與原因，以及重新掃描的結果。如果什麼都沒修好，就刪除這個分支。

### Runtime（Dockerfile）

```bash
node dist/cli.js runtime path/to/repo                  # 報告
node dist/cli.js runtime path/to/repo --fix            # 把 base image 釘到修好的版本
node dist/cli.js runtime path/to/repo --fail-on risk --json
```

有些最嚴重的漏洞不在任何套件裡：Node2Shell（CVE-2026-111497）是 **Node.js 內建**的 Brotli 解碼器越界寫入，同一個上游 bug 也在 .NET 8.0.33 修掉。lockfile 掃描看不到它們，`apt-get upgrade` 也修不到，因為官方映像不是用 OS 套件安裝 runtime 的。`runtime` 會讀所有 Dockerfile（含子目錄），檢查它們所用的 Node.js 和 .NET 映像：

- **固定版本的 tag**（`node:22.20.0-slim`、`dotnet/aspnet:8.0.30`）：列出同一條版本線後續版本修掉的漏洞。Node.js 用 Node.js 安全團隊的漏洞索引，另外也會列出索引還沒收錄、但已被標成安全性更新的新版本，所以 Node2Shell 在發布當天就抓得到。.NET 用 Microsoft 發行資料中的 CVE 清單。
- **浮動 tag**（`node:22-bookworm-slim`、`aspnet:8.0`）：實際版本取決於 build 當下 registry 或鏡像快取給的是哪一版，重 build 不一定拿得到修補，所以會列出並釘版。
- 90 天內或已經**結束支援**（EOL）。
- 不會出貨的 build stage 會列出，但不會讓 build 失敗。`FROM` 行和 `ARG` 預設值都看得懂，registry 前綴（`nexus:8443/library/node`）也沒問題。

`--fix` 會把每個受影響的 `FROM`（或它取版本用的 `ARG`）改成同一條版本線的最新版，保留變體後綴（`-bookworm-slim`、`-noble-chiseled`），不會更動主版本。`@sha256` digest 會被拿掉並提示，因為新的 digest 要 pull 之後才知道。改完後請重新 build 並部署。

#### 跨執行的記憶

同一次執行裡，某一輪修復失敗後，下一輪會看到失敗輸出和前面試過的做法。跨執行時，`fix` 和 `mitigate` 會把**經驗**存在 `.autofix-cve/memory.json`：針對每個套件與版本升級，記錄成功的做法（模型怎麼改程式、改了哪些檔案），以及失敗的做法和原因（哪個驗證指令失敗，或是因為越界而被回滾）。下次遇到同一個套件，不論是同一次還是之後的執行、在筆電上還是全新的 CI runner 上，最相關的經驗都會放進 prompt：同類型的修復與相同目標主版本優先，成功的排在失敗之前，新的排在舊的之前。

只記錄工具自己確認過的結果，不記錄模型自行決定保留的筆記，所以每筆經驗的可靠程度等同於背後的驗證指令。這是一般的 JSON 檔，可以和其他修改一樣 commit 並 review；模型無法修改它，每次讀取和寫入都會出現在稽核紀錄裡。`AUTOFIX_MEMORY=/shared/memory.json` 可以讓多個 repo 共用經驗，`--no-memory` 則完全不使用。

### Mitigate（還沒有修補版時）

```bash
node dist/cli.js mitigate path/to/project
```

有時候根本沒有版本可以升級：npm 上的 `xlsx` 0.18.5 有 prototype pollution 和 ReDoS 兩個漏洞，修好的版本卻從未發布到 npm。`mitigate` 會找出每個「沒有修補版、但你的程式有呼叫到」的漏洞，把公告內容和**你自己的呼叫處**交給模型，請它在那裡加上防護：輸入驗證、大小限制、移除危險的 key，或改用同一個 API 較安全的選項。防護套用後會跑你的驗證指令，失敗就回滾（並帶著失敗訊息再試一輪）。絕不會修改依賴清單、lockfile 或已安裝的套件，模型也可以回答「這裡沒有可加的防護」。

在 `xlsx` 的例子中（一輪，$0.04），它在 `parseUpload` 裡替 `XLSX.read` 加上型別與 10 MB 大小檢查，並在解析前後比對 `Object.prototype`，一旦被污染就還原並拒絕這個檔案；同時也說明了仍然可被利用的部分：精心構造的小檔案仍可能在大小上限內觸發 ReDoS，應該放到 worker 並設逾時，或改用 SheetJS CDN 上的 0.20.2。

防護會連同它加入的程式碼記錄在 `.autofix-cve.json`。這些漏洞仍會出現在所有報告中，只要那段程式碼還在，就會標示 `mitigated at call sites` 並附上剩餘風險（程式碼被改掉，標示也會跟著消失）。`scan --vex` 會把它們寫成 `not_affected` / `inline_mitigations_already_exist`。一旦有修補版發布，請盡快用 `fix` 升級。

### Audit（一次看全部）

```bash
node dist/cli.js audit . --sbom api.cdx.json
```

`audit` 會掃描目錄底下所有 lockfile、Dockerfile 裡的 Node.js 與 .NET runtime，以及指定的 SBOM，再把**同一個漏洞出現在好幾個元件**的情況放在最上面，並列出各自的修法：

```
CVE-2026-111497  src: expose `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`
  brotli 1.0.9-2 (libbrotli1)  image.cdx.json        → brotli 1.0.9-2+deb12u1
  Node.js 22.20.0              api/Dockerfile:1      → FROM node:22.23.4-bookworm-slim
  .NET 8.0.30                  backend/Dockerfile:1  → FROM mcr.microsoft.com/dotnet/aspnet:8.0.33
```

這就是 Node2Shell：同一個上游 Brotli bug，同時被打包進 Node.js、.NET 和 Debian 的 `libbrotli1`。只升級其中一個，其他地方仍然有漏洞，而且沒有任何單一掃描器會同時列出這三處。比對依據是 CVE 編號，包含 Debian 公告所指的 CVE；至於漏洞索引還沒收錄的 Node.js 安全性更新，CVE 取自該版本的 changelog。後面接著每個來源一行的摘要。`--json` 輸出完整結果；`--fail-on any|high|risk` 可以把它當成閘門（預設只產生報告）。

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
          fail-on: likely      # any | likely | high | risk | none
```

這個 action 會掃描、把 Markdown 表格寫進 job summary、把 SARIF 報告上傳到 code scanning；專案有 backport 時也會執行 `verify`。Alert 會出現在 lockfile 的套件項目上，**也會出現在呼叫 advisory 點名的 API 的那一行程式碼**。可用的輸入：`path`、`recursive`、`baseline`、`min-severity`、`fail-on`、`include-dev`、`sarif-file`、`upload-sarif`、`verify`。

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

模型從不執行任何東西。呼叫時不提供任何工具，它只能回傳 JSON：判斷、說明，或 search/replace 修改。要執行哪些指令（安裝、你的驗證指令、PoC）由這個工具決定，不由模型決定，所以就算有人透過 advisory 內文做 prompt injection，也沒有指令可以劫持。

Advisory 內文和上游 diff 對 LLM 來說都是不可信的輸入，所以會限制它的輸出：

- 程式碼修改只能是精確的 search/replace，不能動 `package.json`、lockfile 或專案以外的任何東西；backport 的修改只能落在被修補的那一個套件內。
- PoC 腳本在 Node.js permission model（`--permission`）下執行：專案唯讀、不能寫檔、不能開子程序、不能載入原生模組，並有 10 秒逾時。
- 必須通過你的驗證指令（backport 還要通過 PoC），修改才會留下。

執行的指令本身也只拿到最少的權限：

- **不帶憑證**。安裝、驗證指令和任何會執行套件程式碼的指令，只拿到 build 需要的環境變數（`PATH`、家目錄與暫存目錄、proxy 與 CA 設定、套件管理工具的設定）。token 與金鑰（`GITHUB_TOKEN`、`AUTOFIX_OPENAI_API_KEY`、`AWS_*`，以及名稱像 token、password、key 的變數）都不會傳下去，所以剛升級、可能遭到投毒的新版本，它的 install script 讀不到這些值。安裝真的需要的變數（例如私有 registry 的 `NPM_TOKEN`）請寫在 `AUTOFIX_PASS_ENV=NPM_TOKEN`。只有負責 push 和開 PR 的 git 與 gh 會看到完整的環境變數。
- **不跑 install script**：`fix` 和 `mitigate` 加上 `--ignore-scripts`，套件的 lifecycle script 完全不會執行。backport 會一併關閉，因為它要靠專案自己的 postinstall 保留修補。
- **範圍驗證（Fail-Closed）**。在 git repo 中，每次修復與 mitigation 結束後，都會比對它聲明要改的檔案（依賴清單、lockfile、模型修改的檔案、`.autofix-cve/`）。只要有其他被追蹤的檔案被改動，或敏感位置出現新檔案（CI 設定、`.npmrc`、`.env`、git hooks、`Dockerfile`），就把修復開始以來的所有變更還原（執行前就存在的未提交修改也會保留原狀），並把這次修復標為失敗、列出那些檔案。套件管理工具會重寫的依賴目錄（`node_modules`、`vendor`、`.venv`、`target`、`obj`、Yarn 的 `.yarn` 與 `.pnp.*`）即使有 commit 進 repo 也視為正常變動；其他位置的未追蹤檔案（通常是 build 產出）只會記錄下來。`--allow-changes <path...>` 可以額外放行，例如有 commit 進 repo 的 build 產出。
- **稽核紀錄**。`fix` 和 `mitigate` 會寫入 `.autofix-cve/audit/<command>-<time>.jsonl`，每個事件一行 JSON：計畫、每個指令的 exit code、耗時與輸出結尾、每次模型呼叫的 prompt SHA-256（prompt 含有你的原始碼，所以不複製原文）和實際套用的完整回覆、範圍驗證、結果與 exit code。`--audit-log <file>` 可改寫到別處，`--no-audit` 關閉。可以留作證據，或把 `.autofix-cve/audit/` 加進 `.gitignore`。
- **自選沙盒**：設定 `AUTOFIX_EXEC_WRAPPER` 後，所有專案指令都在裡面執行，`{dir}` 換成專案目錄，指令接在最後一個參數，例如 `docker run --rm -v {dir}:/work -w /work node:22 sh -c`。在那裡加上 `--network none` 就能離線跑驗證指令（安裝仍需連 registry）；Linux 上也可以用 `bwrap`/`firejail`。

## 鏡像與離線使用

所有對外服務都可以改指向鏡像，適用於只能透過 Nexus 之類的 proxy 上網的內網環境：

| 變數 | 預設 | |
|---|---|---|
| `AUTOFIX_OSV_URL` | `https://api.osv.dev/v1` | OSV API（漏洞資料） |
| `AUTOFIX_NPM_REGISTRY` | `npm_config_registry`，沒有則 `https://registry.npmjs.org` | npm registry，用來排除已 deprecated 的版本 |
| `AUTOFIX_PYPI_URL` | `https://pypi.org/pypi` | PyPI JSON API，用來排除已 yank 的版本 |
| `AUTOFIX_CRATES_INDEX` | `https://index.crates.io` | crates.io sparse index |
| `AUTOFIX_GITHUB_API` | `https://api.github.com` | GitHub API（GitHub Enterprise），backport 抓 diff 用 |
| `AUTOFIX_EPSS_URL` | `https://api.first.org/data/v1/epss` | EPSS 分數：API、同格式的本機 JSON 檔，或 `off` |
| `AUTOFIX_KEV_URL` | CISA 官方 feed | KEV 清單：URL、本機 JSON 檔，或 `off` |
| `AUTOFIX_NODE_RELEASES_URL` | `https://nodejs.org/dist/index.json` | Node.js 發行清單（`runtime`） |
| `AUTOFIX_NODE_VULNS_URL` | Node.js security-wg 的 `vuln/core/index.json` | Node.js 漏洞索引（`runtime`） |
| `AUTOFIX_NODE_CHANGELOG_URL` | Node.js 的 `doc/changelogs/CHANGELOG_V{major}.md` | 索引還沒收錄的安全性更新所修的 CVE（`runtime`） |
| `AUTOFIX_NODE_SCHEDULE_URL` | Node.js Release 的 `schedule.json` | Node.js EOL 日期（`runtime`） |
| `AUTOFIX_DOTNET_RELEASES_URL` | Microsoft 的 `release-metadata/{channel}/releases.json` | .NET 發行資料，`{channel}` 會換成例如 `8.0`（`runtime`） |

透過 npm 或 npx 執行時，會自動使用 `.npmrc` 設定的 registry。連不到 registry 時工具照樣可用，只是無法排除 deprecated 或 yank 的版本。

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

#### OpenAI 相容端點

無法使用本機 CLI 的情況（例如在 CI 中走公司的 LLM gateway），設定 `AUTOFIX_LLM=openai` 就會改呼叫任何 OpenAI 相容的 `/chat/completions` 端點：

| 變數 | 預設值 | |
|---|---|---|
| `AUTOFIX_LLM` | `cli` | `cli` 或 `openai` |
| `AUTOFIX_OPENAI_BASE_URL` | （必填） | 例如 `https://gateway.example.com/v1` |
| `AUTOFIX_OPENAI_API_KEY` | 無 | 以 `Authorization: Bearer …` 送出 |
| `AUTOFIX_MODEL` | （必填） | 端點提供的模型 |
| `AUTOFIX_OPENAI_JSON` | `json_schema` | `json_schema`、`json_object`，或 gateway 不支援 `response_format` 時用 `none`，改把 schema 寫進指示中 |
| `AUTOFIX_PRICE_INPUT` / `AUTOFIX_PRICE_OUTPUT` | `0` | 每百萬 token 的美元價格，讓 `--max-cost` 能計算花費 |

回覆即使包在 Markdown 區塊或夾雜文字中也能解析；不是合法 JSON 或缺少必要欄位的回覆會重試一次，仍失敗才讓這次修復失敗並回滾。`doctor` 會檢查端點能否用設定的 key 回應。

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
- [x] 掃描與修復 .NET 專案（`packages.lock.json` / `project.assets.json`、Central Package Management，在 CI 中用 dotnet 實際驗證）
- [ ] Python backport：刻意暫不實作，原因有兩個。Python 的套件管理器沒有 post-install hook，修改 site-packages 的修補會在下一次 `uv sync` / `pip install` 時悄悄消失；而且 Python 沒有像 Node 那樣的內建 permission sandbox，執行模型根據不可信的 advisory 寫出的 PoC 時，無法做到同等程度的隔離。

## 授權

MIT
