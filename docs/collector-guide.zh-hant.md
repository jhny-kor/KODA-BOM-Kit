# KODA BOM Kit — 收集指令與輸出檔案

<!-- koda-doc-nav -->
<p align="center">
  <a href="collector-guide.md"><img src="badges/en.svg" alt="English"></a>
  <a href="collector-guide.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="collector-guide.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="collector-guide.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="collector-guide.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="collector-guide.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="collector-guide.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="collector-guide.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="collector-guide.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="collector-guide.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

## 選擇收集範圍

在運作中的主機上執行，可收集作業系統、套件、容器及有權讀取的硬體資料。目錄掃描僅涵蓋指定目錄樹，映像掃描則讀取已匯出的 Docker 或 OCI 封存檔。每次執行選擇一種輸入。預設上限為一百萬個一般檔案與 30 分鐘。`--max-files 0 --timeout 0` 可解除這兩項上限，但權限、檔案系統邊界及封存檔解析限制仍然有效。

```sh
sudo ./koda-bom --output-dir ./reports --cyclonedx-17
./koda-bom scan --image-archive ./application-image.tar --output-dir ./images
```

## 掃描一個或多個目錄

腳本接受目標目錄及選用的輸出父目錄，以 `--no-context` 執行，且不接受 `/` 作為目標。含空白的路徑要加引號。用 `--exclude-dir` 排除目錄，以 `--exclude` 排除符合模式的項目。多個目標不得重疊，排除目錄要使用絕對路徑。合併後會保留 `target-1`、`target-2` 與實際發現位置。

```sh
./scan-directory.sh "/opt/application" ./results --exclude-dir logs --exclude '**/*.bak'
./koda-bom scan --target /opt/application --target /opt/runtime \
  --exclude-dir /opt/application/cache --exclude-dir /opt/runtime/logs --output-dir ./results
```

## 讀取核心即時修補證據

主機掃描從 sysfs 讀取核心即時修補狀態。選用腳本會查詢已安裝的 Canonical Livepatch、Ksplice 或 Uptrack 用戶端並整理輸出。匯入的報告必須符合這次開機及核心，且在 24 小時內取得，才算作目前狀態。缺少項目無法判定某個 CVE 是否已修補。

```sh
sudo ./collect-livepatch-status.sh /var/tmp/koda-results --max-files 0 --timeout 0
sudo ./koda-bom scan --livepatch-evidence /path/to/canonical-livepatch.json --output-dir ./host
```

## 重建運作關係或合併清單

主機 OBOM 關聯接聽通訊端、程序與已安裝的套件。單憑本機繫結位址無法判斷外部是否可連線。可用 `--kubernetes-evidence` 或 `--network-evidence` 匯入對應觀測。將 `set_dir` 設為分割後含 `bom-set.json` 的目錄，保留關係檔與校驗和。採用舊檔名 `mlbom.cdx.json` 的封存資料集也可合併。

```sh
./koda-bom obom --collection ./previous-host-scan --output-dir ./replayed --cyclonedx-17
./koda-bom bom-split --collection ./previous-host-scan --output-dir ./separated
./koda-bom bom-merge --set "$set_dir" --output-dir ./merged
```

## 為其他清單提供證據

將 AI 收集器指向本機模型目錄。SaaS 與製造流程需要服務或製程清單。用 `--asset-evidence` 匯入 Redfish 裝置、韌體或密碼資產證據。僅在 SHA-256 相符時，才會將建置清單與實際產物連結。輸入格式請見文末指南。

```sh
./koda-bom ai-bom --model-dir /srv/models/Qwen --output-dir ./models
./koda-bom scan --build-sbom ./supplier.json --build-artifact /opt/app/product.bin --output-dir ./reports
```

## 匯入 IBM AIX 與 Oracle 紀錄

在 AIX 上執行收集腳本，然後在 Linux 分析主機上匯入。提供 Oracle Home 擁有者儲存的 OPatch 輸出，也可提供 DBA 匯出的 SQL 修補歷程。最多支援八個不同的 Home。判定 Listener 版本需要同一 Home 的證據。請依適用的廠商公告核對修補程式 ID。

```sh
./collect-aix-evidence.sh ./aix-evidence \
  --oracle-home /actual/db/home ./db-opatch.txt --sqlpatch ./db-sqlpatch.csv \
  --oracle-home /actual/grid/home ./grid-opatch.txt
./koda-bom aix-import --evidence ./aix-evidence --output-dir ./results
```

## 辨識已部署的相依項目

npm 與 pnpm 依實際安裝位置、peer 解析結果及版本判定相依關係。靜態 JavaScript 涵蓋 jQuery、jQuery UI 與 Fancytree。Go 使用內嵌建置資訊，Rust ELF 讀取 cargo-auditable 資料。.NET 將 .deps.json 與部署的受控 DLL 比對，Ruby 使用已安裝的 gemspec。Java 保留巢狀 WAR、EAR 與 Spring Boot 函式庫的路徑。座標不明的項目維持未解析狀態。

## 比對部署檔與供應商清單

提供一個 WAR 或 EAR，以及含該封存檔本身 SHA-256 的 CycloneDX 1.4–1.7 或 SPDX 2.3 文件。在 `reconcile.json` 查看 `common`、`observedOnly`、`supplierOnly` 與 `unresolved`。向 Tracker 提交實測 SBOM。部署檔上限為 512 MiB，供應商 SBOM 為 32 MiB。

```sh
./koda-bom reconcile --artifact /opt/app/app.war \
  --supplier-sbom /path/to/supplier.cdx.json --output-dir ./comparison
```

## 驗證涵蓋範圍

在建置或測試主機上，以 KODA、Syft、Trivy 比對同一份未變動的部署內容。比較腳本需要 Python 3.11 以上版本。透過 `--expected` 指定已確認的元件及相依關係，以 `--baseline` 檢查迴歸。選用的 Tracker 測試會上傳至指定測試服務。可透過 `--normalized-bom-command` 核對儲存後的關係圖。

```sh
python3 scripts/compare-sbom-inventory.py \
  --deployment /data/deployment --output-dir /data/qa/inventory-01 \
  --koda /opt/qa/koda-bom --syft /opt/qa/syft --trivy /opt/qa/trivy \
  --expected /data/qa/expected.json --require-complete
```

## 解讀收集結果

將 `run_dir` 設為收集器輸出的路徑。結束碼 0 表示完成、3 表示部分結果、2 表示失敗。在 `collection.json` 查看上限、遺漏與錯誤，在 `context.json` 查看執行時關係，在 `assets.json` 查看裝置或憑證證據。每個容器或映像目錄均有獨立校驗和。僅憑版本與日期無法判斷弱點狀態。

```sh
(cd "$run_dir" && sha256sum -c SHA256SUMS)
```

## 在另一台主機建置

建置主機需要 Go 與 Python 3。此版本使用 Go 1.26.11。使用其他 Go 時需提供已驗證的執行檔及 SHA-256。離線建置需要事先填妥的模組快取。發行封存檔適用於 Linux amd64，原始碼也能建置 Linux ARM64 執行檔。建置資訊寫入 `release.json`。

```sh
VERSION=0.1.8 GOPROXY=off ./scripts/build-release.sh \
  --go /path/to/go1.26.11/bin/go --go-sha256 "$trusted_go_sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o koda-bom ./cmd/koda-bom
```

## 文件

- [離線部署與結果核對](air-gapped.zh-hant.md)
- [硬體、密碼與運作證據](asset-inventory.zh-hant.md)
- [服務、AI 模型與製造流程清單](additional-bom.zh-hant.md)
- [支援範圍與收集限制](support-matrix.zh-hant.md)
- [建置與驗證步驟](verification.zh-hant.md)
- [測試紀錄與驗證範圍](verification-results.zh-hant.md)
