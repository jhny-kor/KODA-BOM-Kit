# 構建與驗證指南

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 0.1.8 提供 Linux amd64 離線壓縮包和 SHA-256 校驗檔案。用可執行檔案的精確雜湊及運行環境識別驗證對象。Linux 主機採集面向 x86_64 和 ARM64，Docker/OCI 歸檔採集面向 linux/amd64。macOS 和 Windows 資產清單使用固定的唯讀系統命令。Windows 實際運行尚未驗證。歷史 VM 結果對應各自記錄的構建。

[發行版 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## 輸出格式與完整性

預設輸出為 CycloneDX 1.6 和 SPDX 2.3。`--cyclonedx-17` 從同一清單增加 1.7。與 `--format cyclonedx` 組合生成兩份 CycloneDX，與 `--format spdx` 組合會在輸出前拒絕。`scan`、`aix-import`、`asset-import`、`platform-inventory`、`reconcile` 和兩個採集腳本支持此選項。根據所選選項核對預期檔案。

| 輸出 | 格式 |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` 檢查本地模式、組件標識、證據、屬性、授權條款含義、依賴、範圍、校驗項遺漏或重復及雜湊。1.7 模式固定到官方 1.7.1 提交 `b29bae660048e0ad2fbc5f2972927b442ce951c4`，來源記錄在 `tests/schemas/provenance.json`。1.6 有 704 個授權條款 ID，1.7 有 811 個。新增 107 個在 1.6 中保存為 `license.name`，在 1.7 中使用 `license.id`。模式通過後仍需檢查 `collection.json` 的部分採集狀態。

## 構建機檢查

在構建機準備 Go、Python、Docker、Go 模塊快取及模式依賴。`trusted_go_sha256` 應為獨立驗證的 Go 可執行檔案雜湊。`GOPROXY=off` 使用預先準備的快取。發佈 QA 拒絕 `python3 -O` 或 `PYTHONOPTIMIZE`。目標伺服器使用打包的可執行檔案。macOS 校驗命令為 `shasum -a 256 -c SHA256SUMS`。

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## 集成測試範圍

對解壓後的最終發行包運行以下命令。斷網前準備所需上游快取。.NET/Ruby 需要 .NET 10 SDK，Go/Rust 需要快取及固定的 ripgrep ELF，也可指定 `--rust-binary`。Fancytree 使用固定的 npm SHA-512 或 GitHub SHA-256。支持的測試加上 `--tracker-root /path/to/tracker` 可驗證本地真實 Tracker 解析器。

`domain_bom_integration.py` 直接執行目標二進位檔案，請在 Linux amd64 上執行。

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

測試涵蓋嵌套 Java、pyz/pex、Go/Rust、安裝來源、目錄邊界、供應商雜湊、PURL 和依賴。Linux 測試資料涵蓋套接字、容器、韌體解析、服務、設置、完整性及證書。AIX 測試檢查 Oracle Home、Listener 和 OPatch。物理 BMC/NIC/OT、真實 Kubernetes 存儲及已訂閱補丁客戶端需要現場證據。

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.8/scripts)

## Linux 內核與 VM 復現

Linux 專用測試必須在 Linux 運行。macOS 可交叉編譯並在相同架構的 Linux 容器執行。VM 使用最終發行包內的檔案。Oracle RHCK `4.18.0-193.el8.x86_64` 和 UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` 分別啓動。簽名 RPM 固定在 `tests/oracle-vm/kernels.json`。保留輸入來源、簽名日誌、QEMU 映像 ID、串口日誌、基線和驗證報告。

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

Oracle runner 使用 QEMU system TCG、4 GiB 記憶體、2 個虛擬 CPU 和專用靜態 PID 1，來賓無網絡或磁盤。檢查 uname、proc、實際加載的 loop 模塊、已安裝與運行內核。Ubuntu 從已認證資料啓動 `6.8.0-47-generic`。GRUB、UEFI/Secure Boot、完整 systemd 啓動、SELinux enforcing、物理驅動及生產服務需另行驗證。Oracle 容器共享宿主內核，只能驗證其用戶空間和 RPM 資料。

[Oracle VM](tests/oracle-vm/README.zh-hant.md) · [Ubuntu VM](tests/ubuntu-vm/README.zh-hant.md)

## 系統調用、資源限制與後續分析

在隔離的構建機容器追蹤最終檔案。ARM64 仿真無法解析 ptrace 寄存器時，`trace-network.sh` 返回 77。可使用 QEMU guest syscall 追蹤，並注明環境。聲稱零次嘗試必須有有效追蹤。可選 livepatch 腳本調用現有供應商客戶端，其守護進程與網絡行為需另行評估。

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

預設限制是選中的普通檔案 1,000,000 個和 30 分鐘。分別測試限制、非法選項、取消、權限、損壞輸入與排除路徑。`--max-files 0 --timeout 0` 解除這兩項限制。記錄實際輸入的耗時和峰值 RSS。並行度 2 不提供硬記憶體上限。Tracker 使用隔離臨時資料庫驗證兩種標準格式。本地安全公告評估依賴輸入規則與觀測。生產部署與 CVE 修復需要相應證據。

## 相關文件

[隔離網絡中的運行與結果檢查](air-gapped.zh-hant.md) · [構建與驗證指南](verification.zh-hant.md) · [驗證結果](verification-results.zh-hant.md)
