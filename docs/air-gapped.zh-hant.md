# 隔離網絡中的運行與結果檢查

<!-- koda-doc-nav -->
<p align="center">
  <a href="air-gapped.md"><img src="badges/en.svg" alt="English"></a>
  <a href="air-gapped.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="air-gapped.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="air-gapped.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="air-gapped.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="air-gapped.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="air-gapped.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="air-gapped.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="air-gapped.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="air-gapped.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.9 離線包面向 Linux x86_64 (amd64)、內核 3.2 及以上。從官方發佈下載壓縮包和配套 `.tar.gz.sha256`。目標伺服器無需新增 Go、Python、Docker 或 jq。NOTICE 標注 jhny-kor 和官方儲存庫。

[發行版 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## 校驗與解壓

將唯一匹配的壓縮包和校驗檔案放在可執行的本地目錄。解壓前檢查歸檔，解壓後檢查內部檔案。校驗和確認傳輸字節，來源應為可信官方發佈。USB 的 noexec 掛載需要複製到允許執行的本地檔案系統。

```bash
set -- koda-bom-linux-amd64-0.1.9-*.tar.gz
if [ "$#" -eq 1 ] && [ -f "$1" ]; then
  pkg=${1%.tar.gz}
  sha256sum -c "${pkg}.tar.gz.sha256" &&
  tar -xzf "${pkg}.tar.gz" &&
  cd "$pkg" &&
  sha256sum -c SHA256SUMS &&
  ./koda-bom version
else
  echo 'Expected exactly one KODA BOM Kit 0.1.9 archive.' >&2
fi
```

## 檢查主機

檢查架構、運行內核和 `doctor`。`supported=true` 表示滿足運行前提。`doctor.kernel` 和 `context.json.runningKernel` 記錄內核。即使 `kernelFlavor=unknown/unconfirmed`，內核版本仍可能已記錄。root 權限可擴展 DMI、BMC、進程和容器可見範圍。

```bash
uname -m
uname -r
./koda-bom doctor
```

## 選擇採集範圍

無參數運行 `koda-bom` 會在 `bom-output/` 建立新目錄，生成合併的 `bom.cdx.json` 和 `boms/` 下七種檔案。AI-BOM 名為 `aibom.cdx.json`。內容及完整性取決於可讀本地證據。Qwen 使用實際模型路徑。H100 資訊在 HBOM，模型設定、頭部和安裝包不能確定當前 GPU 分配或實際服務設定。

```bash
sudo ./koda-bom
rc=$?
printf '%s\n' "$rc"

./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./qwen-results
```

```text
bom.cdx.json
boms/sbom.cdx.json
boms/hbom.cdx.json
boms/cbom.cdx.json
boms/obom.cdx.json
boms/saasbom.cdx.json
boms/aibom.cdx.json
boms/mbom.cdx.json
```

目錄採集使用 `--no-context`，輸出應位於輸入範圍外。目錄腳本拒絕 `/`。單目錄腳本的 `--exclude-dir` 可用相對路徑，多個目標不能重疊且排除目錄須用絕對路徑。檔案和時間限制由全部目標共享。選定範圍外的依賴可能無法觀測。

```bash
sudo ./scan-directory.sh '/opt/My Application' /var/tmp/koda-bom-results \
  --exclude-dir logs --exclude-dir cache

./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs \
  --output-dir /var/tmp/koda-bom-results
```

## Livepatch 採集

可選腳本查詢已有 Ksplice、Uptrack、Canonical 客戶端，清理證據後執行 scan，並在結果旁保存清理後的證據。立即保存 `$?`。客戶端查詢上限為 30 秒，有效內核查詢為 10 秒，解除 scan 超時不會解除這些上限。供應商客戶端與守護進程有各自的網絡行為。

```bash
sudo ./collect-livepatch-status.sh /var/tmp/koda-bom-results
rc=$?
printf '%s\n' "$rc"
```

## 限制與退出狀態

預設選中普通檔案上限 1,000,000 個，時間 30 分鐘。`--max-files 0 --timeout 0` 解除這兩項限制，Ctrl+C 可取消。權限、排除、符號鏈接邊界、單檔案 2 GiB 及映像解壓限制仍適用。`--no-containers` 跳過容器和閒置映像，`--no-images` 跳過停止容器和閒置映像。0 為完成，3 為部分採集且有結果，2 為失敗。其他異常退出也需檢查。

```bash
sudo ./koda-bom scan --output-dir /var/tmp/koda-bom-results \
  --max-files 0 --timeout 0 --cyclonedx-17
rc=$?
printf '%s\n' "$rc"
```

## 定位與驗證結果

使用命令打印的實際結果目錄。腳本先輸出 doctor 與證據，最後輸出結果路徑。將 `result` 設為此路徑。root 創建的檔案可能需 sudo 查看。檢查根清單和各容器/映像清單，並保留部分採集原因。

```bash
result='/path/to/actual-result'
sudo ls -lh "$result"
sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh "$result"
sudo sh -c '
  cd "$1" || exit 1
  for d in containers/*/ images/*/; do
    [ -d "$d" ] || continue
    (cd "$d" && sha256sum -c SHA256SUMS) || exit 1
  done
' sh "$result"
```

## 讀取採集與補丁狀態

`collection.json` 記錄 `status`、`packageCount`、`packageTypes`、`limits`、`filesystemFileCount`、`issues`、主機標識、來源、完整性及容器狀態。檔案數為遍歷選中的普通檔案。`file_limit_exceeded` 包含 `limit` 和 `observed`。`context.json` 保存內核、進程、監聽、服務、設置及補丁，`assets.json` 保存硬件、韌體及證書證據。

```bash
sudo cat "$result/collection.json"
sudo cat "$result/context.json"
```

`applied` 為內核直接觀測，`reported-applied` 為客戶端報告。`disabled`、`transitioning` 保留對應狀態。`stale`、`identity_mismatch`、`unknown` 需要更多證據。結合當前狀態和 `patches[].state`，因為 `reportedState` 可能保留舊報告。超過 24 小時、不同啓動/內核、超限未來時間不能證明當前應用狀態。還要檢查 Canonical Last-Check/CheckState。未觀測及 `not-reported-patched` 需結合內核/供應商證據解釋。

`integrity.findings[].state=modified` 或 `missing` 表示內容不符或缺失。`bindScope=all-interfaces` 表示綁定範圍，防火牆暴露需另行檢查。`unidentifiedExecutables` 表示無法關聯安裝包，`reboot.recommended=not_observed` 表示未見重啓信號。結合身份、上下文和限制解釋結果。

## 供應商對照與保存

WAR/EAR 供應商 SBOM 必須綁定實際 SHA-256。缺失或不符時退出 2。檢查 `reconcile.json` 和部分採集原因。保存包含清理後 livepatch 證據的完整父目錄，並計算導出歸檔校驗和。

```bash
./koda-bom reconcile --artifact /opt/application/app.war \
  --supplier-sbom /var/tmp/supplier.cdx.json --output-dir /var/tmp/koda-bom-results

archive="/var/tmp/koda-bom-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
sudo tar -C /var/tmp -czf "$archive" koda-bom-results
sudo sha256sum "$archive"
```

## 上傳與後續分析

向兼容 Tracker 提交 `sbom.cdx.json` 或 `sbom.spdx.json`。容器/映像各有自己的標準 SBOM。collection、context、Syft 清單作為附件證據保存。上傳超時單獨設定。採集為公告分析提供輸入，當前補丁效果和 CVE 修復需獨立證據。歷史 VM 和各發行版測試範圍見驗證記錄。

## 相關文件

[隔離網絡中的運行與結果檢查](air-gapped.zh-hant.md) · [構建與驗證指南](verification.zh-hant.md) · [驗證結果](verification-results.zh-hant.md)
