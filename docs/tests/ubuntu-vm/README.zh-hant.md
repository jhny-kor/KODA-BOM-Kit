# Ubuntu 24.04.1 真實核心 VM 驗證

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="README.pt.md"><img src="../../badges/pt.svg" alt="Português"></a>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

這是 KODA BOM Kit 測試工具，不屬於隔離網路部署執行檔的相依項。它使用自訂 initramfs 直接啟動 Ubuntu Base **24.04.1 amd64** 和官方 Ubuntu 核心 **6.8.0-47-generic / 套件 6.8.0-47.47**。QEMU user-mode 或目錄 fixture 無法建立真實核心啟動證據。

Ubuntu Base 原件取自封存 Ubuntu 發行鏡像站。使用 Ubuntu CD Image Automatic Signing Key (2012) `843938DF228D22F7B3742BC0D94AA3F0EFE21092` 驗證 SHA256SUMS.gpg。透過已認證 rootfs 內的 Ubuntu archive keyring，驗證官方 Snapshot 服務的 2024-10-18 noble-updates InRelease。驗證鏈連結簽署的 Release → Packages.xz → 兩個 DEB 的 SHA-256 和大小。保留所有輸入 URL、校驗和、簽章日誌和 Docker 映像 ID。

建置主機需要 Go、Python 3/`jsonschema`、Docker、GnuPG（`gpg`/`gpgv`）。重用 Oracle VM 工具映像。無需在目標伺服器安裝這些工具。在專案根目錄執行以下命令，將 `<ID>` 替換為實際執行 ID。

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go` 重用 Oracle 工具的有界匯出和獨立 baseline 設計。Ubuntu 的 loop 驅動程式內建，因此測試載入真實 `dummy.ko` 驗證模組觀測。獨立記錄執行中的 uname、proc release、OS、收集器 SHA、已載入模組，再將兩份 SBOM 與固定官方 schema、校驗和、DEB 原始版本/source/PURL、已安裝核心/模組比對。每次提供新的最終二進位檔時都要重新執行 prepare、run、validate。

測試 rootfs 用 `dpkg --unpack` 解開原始 DEB 並產生真實 dpkg 資料庫。允許相依覆寫後保留 unpack 狀態，無法據此確認一般 apt 安裝與設定已完成。完整 systemd 啟動、GRUB、UEFI/Secure Boot、正式環境服務、實體硬體需另外驗證。QEMU 不連接網路介面或磁碟，Docker 使用 `--network none`、唯讀 rootfs 並移除 capability。實際商業或訂閱 live patch 安裝不在此測試範圍內。

0.1.3 驗證傳入 `--max-files 0 --timeout 0` 解除收集器的兩項限制。測試 PID 1 的獨立 11 分鐘 watchdog 和主機 QEMU 執行器逾時仍保留。

一併保留 provenance、簽章日誌、dpkg 日誌、`command.json`、`serial.log`、`boot-report.json`、`baseline.json`、兩份 SBOM 與 `validation.json`。部分收集結束碼 3 維持為 3，不改成完整收集結束碼 0。
