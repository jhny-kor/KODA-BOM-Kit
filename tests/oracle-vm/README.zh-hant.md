# Oracle Linux 8.2 核心直接啟動驗證工具

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../docs/badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../docs/badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../docs/badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="README.ko.md"><img src="../../docs/badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../docs/badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../docs/badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../docs/badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../docs/badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../docs/badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../docs/badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../docs/badges/release.svg" alt="v0.1.8"></a>
  <a href="../../LICENSE"><img src="../../docs/badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`init.go` 是 KODA BOM Kit 的 **驗證 VM PID 1**。`//go:build ignore` 使它不參與一般 Go 套件測試。請使用下列命令明確建置。

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python、Go、Docker 和 QEMU 是建置 PC 上的驗證工具。將 `koda-bom` 執行檔交付給隔離網路目標伺服器。此工具及 Python 直譯器不是部署執行檔的相依項。

## 重現步驟

執行器在 ARM64 建置主機的 QEMU 容器中透過 TCG 模擬 x86_64。客體分配 4 GiB RAM、2 vCPU，容器記憶體上限為 6 GiB。在外部建置 PC 的專案根目錄執行。將 `<ID>` 替換為 `run.py` 輸出的實際 ID，並保留過往報告。

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

驗證主機需要 `jsonschema`，使用 `tests/schemas` 固定的官方 schema 離線檢查。準備階段下載需要連網，核心 VM 無外部連線。標籤對應映像可能變動，因此保留實際使用的映像 ID。

`prepare.py` 檢查 [kernels.json](kernels.json) 固定的 4 個 RPM（共 120,245,036 位元組）的 SHA-256、大小及 Oracle Linux 8 簽章金鑰指紋。它向全新 Oracle 測試容器的 RPM 資料庫匯入公鑰，用 `rpm -Kv` 檢查簽章，再以 `--nodeps --noscripts --notriggers` 安裝核心。這會建立驗證核心映像、模組和 RPM 中繼資料所需的檔案系統。一般安裝指令碼、dracut、GRUB 設定不在此流程中。

在既有工作目錄以最終發行二進位檔重新執行 `prepare.py`，使用快取的核心/RPM 檔案系統重建收集器、驗證 PID 1 和 initramfs。重新啟動兩個核心 VM，並將 **最終二進位檔 SHA-256** 與 baseline 比對。舊建置的 VM 結果無法驗證新發行。

保留 `input-provenance.json`、`rpm-signature-install.log`，以及每次執行的 `command.json`、`serial.log`、`boot-report.json`、`validation.json`、`results/baseline.json`、兩份 SBOM 與校驗和。provenance 記錄 RPM、核心、initramfs、PID 1、收集器雜湊及 Oracle/QEMU 映像 ID。另用發行驗證報告將證據連結到發行封存檔的 SHA-256。

## 客體準備

驗證 initramfs 包含 Oracle Linux 8.2 檔案系統、兩個已安裝核心的 RPM 資料庫、`/boot` 核心映像、兩個 `/lib/modules` 樹、待測 `/koda-bom` 和本工具 `/init`。RHCK、UEK 必須各自透過自己的核心映像直接啟動。僅執行容器或 QEMU user-mode 不能建立這項啟動證據。可將從官方核心 RPM 擷取且版本相符的模組放到以下位置。

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

工具記錄模組 SHA-256，並透過 `init_module` 嘗試載入。模組缺漏、已載入或因簽章與相依項失敗時，分別記錄狀態和錯誤。比較 `loadedModulesAfter` 與收集器的 `loadedModules` 以確認實際載入。未觀測到模組不能證明功能不存在。

QEMU 不連接外部網路介面或虛擬磁碟。執行器使用 `-accel tcg,thread=single -cpu max -smp 2 -m 4096`。測試客體使用 `random.trust_cpu=on` 避免早期啟動 `getrandom` 等待。此參數不是正式環境設定建議。在主機端保留實際 CPU/加速模式及核心、RPM、initramfs、收集器校驗和。

## 執行與收集

工具掛載 `/proc`、`/sys`、`/dev`、`/tmp`、`/results` 並設定合成主機名稱。獨立 baseline 記錄 uname、`/proc/sys/kernel/osrelease`、OS release、模組載入前後清單、VM 核心命令列、收集器校驗和。主機名稱和核心命令列僅用於此合成 VM 證據，產品一般收集政策保持原樣。收集器按以下命令執行一次。

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

不傳 `--target /payload`，使用預設 live-host 模式。0.1.3 驗證將檔案數與時間上限設為 0 以解除限制。驗證 PID 1 的獨立 11 分鐘 watchdog 和主機 QEMU 逾時保留以回收資源。stdout、stderr 各限 1 MiB，寫入獨立檔案。結束碼、耗時與錯誤保存至 `/results/baseline.json`。結束碼 3 表示部分收集，必須保留為 3。

結果透過序列輸出，在下列標記之間以 **base64(gzip(tar))** 傳輸。

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

若未壓縮總量超過 256 MiB 或 10,000 個檔案，僅匯出說明失敗原因的 baseline。匯出後嘗試 sync 和 poweroff。失敗時 PID 1 維持執行以避免 kernel panic。客體逾時時由主機執行器終止 QEMU。

## 必要檢查項目

- baseline 的 uname 與 proc release 一致，RHCK/UEK 分別啟動預期版本。
- `context.json.mode=live-host` 和 `runningKernel` 與獨立 baseline 完全一致。
- UEK 回報 `kernelFlavor=UEK`，RHCK 依目前輸出約定回報 `RHCK-compatible`。
- 原生清冊保留兩個已安裝核心及各 RPM 的 epoch/version/release/arch/source package。
- 區分已安裝核心與 context 識別的目前執行核心。
- 模組 `metadata.kernelVersion`、`versionMagic` 與各安裝樹相符，已載入模組清單與作用中核心 baseline 一致。
- 兩份 SBOM 的 schema 與校驗和通過，收集失敗和部分狀態如實回報。

## 驗證範圍限制

- 啟動真實 Oracle RHCK/UEK 客體核心。實體 x86_64 伺服器驗證需要另外執行。
- 以自訂 initramfs 執行 Oracle Linux 8.2 使用者空間及官方核心。完整 systemd 啟動、GRUB 安裝、UEFI/Secure Boot、SELinux enforcing、正式環境服務整合不在測試範圍內。
- `loop` 測試檢查一個真實模組的載入與觀測，不涵蓋所有驅動程式與硬體。不得將非作用中核心的已安裝模組視為已載入。
- 接受結束碼 `3` 和 `collection.status=partial`，同時保留原因。核心識別、標準輸出與完整性檢查通過，不代表已完整收集所有檔案。
