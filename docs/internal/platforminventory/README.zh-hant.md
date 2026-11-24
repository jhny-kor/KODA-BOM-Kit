# 原生平台觀測

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

KODA BOM Kit 的 `Collect(ctx)` 使用目標系統已安裝的工具進行有界觀測。命令引數固定，每條命令限時 60 秒、輸出上限 32 MiB。寫入 SBOM 前會篩選欄位。序號、UUID、使用者名稱和應用程式完整路徑會被排除。本機路徑僅參與元件識別碼的雜湊計算。

macOS 上使用 `/usr/sbin/system_profiler` 取得硬體、軟體和應用程式中繼資料。收集器輸出系統韌體、OS 載入器、CPU 和應用程式，並在 OS 版本字串中保留 OS 組建編號。部分應用程式可能缺少版本或中繼資料。

Windows 上透過不載入設定檔的系統 PowerShell 讀取 CIM computer、BIOS、OS、QuickFixEngineering 記錄，以及電腦和目前使用者的解除安裝登錄項目。保留 OS 組建編號和架構。QuickFixEngineering 僅涵蓋自身回報的更新。登錄清冊無法列舉每個使用者設定檔、Store 應用程式或內嵌相依項。收集器會記錄這些涵蓋範圍限制。

使用 `KODA_TEST_NATIVE_PLATFORM=1 go test -v ./internal/platforminventory` 執行 macOS 原生驗證。Windows 解析 fixture 和交叉編譯驗證原始碼結構。實際 Windows 執行驗證需要 Windows 目標。
