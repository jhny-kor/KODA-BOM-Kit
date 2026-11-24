# 驗證結果

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification-results.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification-results.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification-results.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <strong>繁體中文</strong>
  <a href="%EA%B2%80%EC%A6%9D%EA%B2%B0%EA%B3%BC.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification-results.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification-results.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification-results.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <a href="verification-results.pt.md"><img src="badges/pt.svg" alt="Português"></a>
  <a href="verification-results.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification-results.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

本頁記錄 KODA BOM Kit 及舊版本的驗證日期、構建雜湊、環境、部分結果與未驗證範圍。當前 0.1.9 的壓縮包、雜湊及運行範圍以官方發佈條目為準。新可執行檔案需要對應的測試證據。

[發行版 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## 2026-11-21 — 拆分與合併

`f0610ca-worktree-00ed83f2acd8` 對兩份 0.1.6 歸檔驗證了 `scan --separate-boms`、`bom-split`、`bom-merge`、`domain-bom`。獨立比較所有原始組件和關係，每次合併新增一條清單根與運行根之間的關係。Ubuntu 的 10 對證書 ID 屬於不同檔案位置，保留全部 20 條記錄，合併後重復 ID 為零。Linux ARM64 使用四種觀測 BOM 和合成 OpenAPI、模型、SLSA、製造輸入，同時將真實 TCP 18443 監聽關聯到 Perl 及其包。模式和雜湊通過，簽名及現場證據真實性需另外核實。

| 封存 | 元件 原始 / 合併 | 關係 原始 / 合併 |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — 運行關係

`f0610ca-worktree-06f22395e26f` 從兩份部分採集歸檔重建 OBOM。套接字按命名空間和進程分別計數。Debian ARM64 將 `127.0.0.1:18443/tcp` 關聯到 `/usr/bin/perl` 和 `perl-base`，檢查 3 個 Redfish 部件號、TLS 聲明示例、2 條構建關係、11 個校驗和。重建 OBOM 逐字節一致。5 個合成 Kubernetes 資源關聯到歸檔的完整容器 ID。生產集群、物理清單和真實 TLS 會話未驗證。

| 封存 | 容器 | 通訊端 主機 + 容器 | 套件關聯 主機 + 容器 | 對照關係 |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — Daybreak 12 項修復

針對舊 KODA-SBOM-Maker `cc86c1b` 的發現完成處理。範圍包括隔離 Go 設置、對解壓的同一輸入計算雜湊、256 層上限和復用雜湊、限制 ZIP/ZIP64 索引、校驗 whiteout、獨佔輸出目錄、公告匹配索引與工作量上限、拒絕 Python 優化模式、驗證根內讀取、安全處理短 ID、識別 RPM epoch 衝突、每批 256 項且可取消的目錄遍歷。

macOS ARM64 的 Go、vet 和發佈守衛通過。Go 1.26.11 / Syft 1.57.1 離線構建靜態 Linux amd64 檔案，306 項校驗通過。斷網 Debian 的 CLI 與目錄測試通過。修改前後保留 88 個包、1 個 OS、20 個設備、15 個驅動，兩次均為帶限制說明的 partial。其他平台通過交叉編譯，實際運行和新內核 VM 回歸不在本輪範圍。

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

Docker Desktop `7.0.14-linuxkit` 中 Linux、Go 和 vet 通過。CPU 與 lscpu 一致，讀取 1,736 個內核選項。Debian 147 個包中僅 1 個本地包未記錄，Rocky 識別 167 個儲存庫包及本地、無記錄安裝。9 個運行容器、14 個停止容器、11 個閒置映像生成 35 份合格 SBOM，約 3 分 30 秒。對應包數 796、71、51 一致。overlay2 保留寫入層 curl 並採集閒置 busybox。被刪除的臨時容器標為 `not_collected`。真實 x86、systemd、Kubernetes/k3s/Podman/CRI-O 及新 VM 未驗證。

## 2026-11-19 — 0.1.6

在 Debian 12、Linux ARM64、Docker Desktop `7.0.14-linuxkit` 測試。確認主機雜湊、真實監聽、16 個運行 Docker 容器及 5 個樹外內核模塊。735 個檔案約 89 MB 的完整性檢查準確發現 1 個故意修改和 1 個移動/缺失檔案。RSA-1024、ECDSA P-384 檢查有效期與弱密鑰，並避免輸出私鑰。硬件、snap/flatpak/conda、部分安全設置使用合成資料。物理 RAID/NIC/BMC、生產 SELinux、其他運行時和新 VM 未驗證。

## 2026-11-18 — 0.1.6-dev

Go、vet、腳本限制和語法檢查通過。Linux amd64/ARM64 採集與真實 macOS ARM64 基礎資產輸出通過模式和校驗和。Windows 僅交叉編譯。檢查已刪除/替換檔案、映像雜湊和本地公告規則。Tracker 本地解析器成功讀取兩種 CycloneDX。生產部署與瀏覽器未驗證。704/811 個授權條款 ID 和新增 107 個的語義被保留。校驗檔案數量隨採集範圍變化。

## 0.1.2–0.1.5 歷史版本

0.1.5 增加 pnpm 和 Maven POM 關係，0.1.4 增加目錄腳本，0.1.3 增加檔案/時間限制。用雜湊關聯提供的 `release.json`、`VERIFICATION.json`、`dist/evidence/v0.1.x/final-verification.json`。0.1.2 為最終檔案重新運行 Ubuntu 和兩種 Oracle 內核。訂閱客戶端安裝及真實補丁應用不在合成腳本測試中。

## 2026-10-29 — 實現與 Oracle VM

初始實現通過 68 項 Linux 檢查及 vet。uid 65534、唯讀檔案系統、無 capability、斷網環境中驗證模式、PURL、canary、失敗狀態和雜湊。Oracle 容器包含 RPM 182、Python 5、binary 2。guest syscall 的網絡及額外 execve 嘗試均為零。隔離 SQLite Tracker 的兩種上傳均為 HTTP 202。小型 0.1.0 樣本在仿真中耗時 0.78 秒、峰值 RSS 219,644 KiB。

Oracle Linux 8.2 VM 啓動簽名 RHCK/UEK，uname/proc 與實際 loop 模塊一致。各有 5,516 個組件，含 RPM 186、內核 2、模塊 5,321、Python 5、binary 2。模塊樹為 RHCK 2,478、UEK 2,843。兩種模式與各 5 項校驗通過。退出 3、partial、context completed，保留受保護檔案、範圍外鏈接、OpenSSH 衝突和 Syft 警告。

| Kernel | 採集 / 總秒數 |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## 證據邊界

初始 VM 使用下列 0.1.0 雜湊。後續發行版各有自己的報告。物理 x86、完整 OS/服務集成、真實供應商補丁尚未覆蓋。QEMU guest trace 與原生 ptrace 環境不同。實時檔案採集可能跨越修改時點，宜選擇低變更窗口或唯讀快照。包版本與未觀測結果本身不能確認 CVE 適用性或修復完成。

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## 相關文件

[隔離網絡中的運行與結果檢查](air-gapped.zh-hant.md) · [構建與驗證指南](verification.zh-hant.md) · [驗證結果](verification-results.zh-hant.md)
