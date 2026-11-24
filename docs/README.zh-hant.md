<h1 align="center">KODA BOM Kit</h1>

<!-- koda-doc-nav -->
<p align="center">
  <a href="../README.md"><img src="badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="README.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/linux.svg" alt="Linux amd64"></a>
</p>
<!-- /koda-doc-nav -->

<p align="center"><strong>以單一離線執行檔收集 Linux 主機上的軟體、硬體及運作證據。KODA BOM Kit 會產生七種 CycloneDX 物料清單、一份合併清單及一份 SPDX 軟體清單。</strong></p>

<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><b>下載 v0.1.9</b></a> ·
  原作者 <a href="https://github.com/jhny-kor">jhny-kor</a> ·
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit">官方儲存庫</a>
</p>

## 快速入門

下載 Linux amd64 壓縮檔與對應的 SHA-256 校驗檔，將兩者複製到目標伺服器的空目錄，再執行下列指令。目標伺服器無須安裝 Go、下載套件或設定弱點資料庫。

```sh
(
  set -eu
  set -- koda-bom-linux-amd64-0.1.9-*.tar.gz
  test "$#" -eq 1 && test -f "$1" || exit 1
  sha256sum -c "$1.sha256"
  tar -xzf "$1"
  cd "${1%.tar.gz}"
  sha256sum -c SHA256SUMS
  ./koda-bom version
  sudo ./koda-bom
)
```

## 輸出檔案

最後一行會顯示在 `bom-output/` 下建立的目錄。合併清單位於 `bom.cdx.json`，七份獨立清單則位於 `boms/`。

| 檔案 | 記錄內容 |
|---|---|
| `boms/sbom.cdx.json` | 已安裝的套件、函式庫與應用程式 |
| `boms/hbom.cdx.json` | 裝置、韌體與驅動程式 |
| `boms/cbom.cdx.json` | 憑證、演算法等密碼資產 |
| `boms/obom.cdx.json` | 實際觀測到的服務、程序、通訊端與套件之間的關係 |
| `boms/aibom.cdx.json` | 本機模型檔、權重及提供的模型中繼資料 |
| `boms/saasbom.cdx.json` | OpenAPI 文件或服務清單所描述的服務，以及代理配置中聲明的後端 |
| `boms/mbom.cdx.json` | 由輸入證據描述的製造與建置流程 |

若無對應證據，個別清單的項目可能為空。請查看該清單的證據狀態與 `collection.json` 瞭解原因。可將頂層的 `sbom.cdx.json` 或 `sbom.spdx.json` 提交至 Tracker。 預設輸出 CycloneDX 1.6 與 SPDX 2.3。加入 `--cyclonedx-17` 即可同時輸出 CycloneDX 1.7。

重新合併時請複製整個 `boms/` 目錄，保留資訊清單、關係檔及校驗和。將 `run_dir` 設為收集結束時顯示的路徑。

```sh
(
  cd koda-bom-linux-amd64-0.1.9-*/ || exit 1
  run_dir='/path/printed/by/koda-bom'
  ./koda-bom bom-merge --set "$run_dir/boms" --output-dir ./merged
)
```

## 文件

- [離線部署與結果核對](air-gapped.zh-hant.md)
- [收集指令與輸出檔案](collector-guide.zh-hant.md)
- [硬體、密碼與運作證據](asset-inventory.zh-hant.md)
- [服務、AI 模型與製造流程清單](additional-bom.zh-hant.md)
- [支援範圍與收集限制](support-matrix.zh-hant.md)
- [建置與驗證步驟](verification.zh-hant.md)
- [測試紀錄與驗證範圍](verification-results.zh-hant.md)

### 原始碼與測試指南

- [匯入外部資產](internal/assetimport/README.zh-hant.md)
- [平台清單](internal/platforminventory/README.zh-hant.md)
- [產品辨識](internal/products/README.zh-hant.md)
- [Oracle Linux VM](tests/oracle-vm/README.zh-hant.md)
- [Ubuntu VM](tests/ubuntu-vm/README.zh-hant.md)

## 授權與著作人標示

KODA BOM Kit 採用 Apache-2.0 授權。原作者與隨附相依套件的授權資訊請見下列聲明。 [Apache-2.0](../LICENSE) · [原作者聲明](../NOTICE) · [第三方聲明](THIRD_PARTY_NOTICES.zh-hant.md)
